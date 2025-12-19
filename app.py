import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

try:
    import psycopg2
    import psycopg2.extras
except Exception:
    psycopg2 = None  # optional locally

# =====================
# App / Config
# =====================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

DATABASE_URL = os.environ.get("DATABASE_URL")
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_UPLOAD_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".pdf"}

# =====================
# Kategorien (Key -> Übersetzungen)
# =====================
CATEGORIES = {
    # Bestehende / typische Kategorien
    "DRINKWATER": {"de": "Trinkwasser", "ar": "مياه الشرب"},
    "FOOD": {"de": "Essen", "ar": "طعام"},
    "SNACKS": {"de": "Snacks", "ar": "وجبات خفيفة"},
    "ENTRY": {"de": "Eintritt / Ticket", "ar": "تذكرة / دخول"},
    "SOUVENIR": {"de": "Souvenir", "ar": "تذكار"},
    "MUSEUM": {"de": "Museum", "ar": "متحف"},
    "METRO": {"de": "Metro/ÖPNV", "ar": "مترو / مواصلات"},
    "BUS": {"de": "Bus", "ar": "حافلة"},
    "FLIGHT": {"de": "Flugticket", "ar": "تذكرة طيران"},
    "OTHER": {"de": "Sonstiges", "ar": "أخرى"},

    # NEU (vom Nutzer gewünscht)
    "TAXI": {"de": "Taxi", "ar": "تاكسي"},
    "TIP_BUS_DRIVER": {"de": "Trinkgeld Busfahrer", "ar": "إكرامية سائق الحافلة"},
    "TIP_HOTEL_STAFF": {"de": "Trinkgeld Hotelmitarbeiter", "ar": "إكرامية موظفي الفندق"},
    "TRAIN_TICKET": {"de": "Zugticket", "ar": "تذكرة القطار"},
    "HOTEL_PAYMENT": {"de": "Hotelzahlung", "ar": "دفع الفندق"},
    "VISA": {"de": "VISA", "ar": "تأشيرة"},
}

# gewünschte Reihenfolge im Dropdown (Key-Liste)
CATEGORY_ORDER = [
    "DRINKWATER", "FOOD", "SNACKS",
    "TAXI", "METRO", "BUS", "TRAIN_TICKET", "FLIGHT",
    "HOTEL_PAYMENT", "TIP_BUS_DRIVER", "TIP_HOTEL_STAFF",
    "ENTRY", "MUSEUM", "SOUVENIR",
    "VISA", "OTHER",
]


# =====================
# DB helpers
# =====================
def get_db():
    """Return a DB connection (SQLite locally, Postgres on Render)."""
    if DATABASE_URL:
        if psycopg2 is None:
            raise RuntimeError("psycopg2 not available but DATABASE_URL is set.")
        return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    conn = sqlite3.connect(str(BASE_DIR / "reisekosten.db"))
    conn.row_factory = sqlite3.Row
    return conn


def _col_exists_sqlite(cur, table: str, col: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())


def ensure_schema():
    """Create/upgrade schema (idempotent)."""
    conn = get_db()
    cur = conn.cursor()

    if DATABASE_URL:
        # users
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            startguthaben_sar DOUBLE PRECISION DEFAULT 0,
            wechselkurs_beleg TEXT
        )
        """)
        # kosten
        cur.execute("""
        CREATE TABLE IF NOT EXISTS kosten (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            datum TEXT NOT NULL,
            kategorie_ar TEXT NOT NULL,
            kategorie_de TEXT NOT NULL,
            beschreibung_ar TEXT NOT NULL,
            beschreibung_de TEXT NOT NULL,
            betrag_sar DOUBLE PRECISION NOT NULL,
            beleg TEXT,
            ohne_beleg BOOLEAN DEFAULT FALSE,
            vorschuss_eur DOUBLE PRECISION,
            genehmigt INTEGER DEFAULT 0,
            genehmigt_von TEXT,
            rejection_reason TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )
        """)
        # add missing columns safely
        # (Postgres has IF NOT EXISTS only for tables, so we try/catch for columns)
        for stmt in [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS wechselkurs_beleg TEXT",
            "ALTER TABLE kosten ADD COLUMN IF NOT EXISTS ohne_beleg BOOLEAN DEFAULT FALSE",
            "ALTER TABLE kosten ADD COLUMN IF NOT EXISTS rejection_reason TEXT",
        ]:
            try:
                cur.execute(stmt)
            except Exception:
                pass

    else:
        # users
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('reisefuehrer','buchhaltung')),
            startguthaben_sar REAL DEFAULT 0,
            wechselkurs_beleg TEXT
        )
        """)
        # kosten
        cur.execute("""
        CREATE TABLE IF NOT EXISTS kosten (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            datum TEXT NOT NULL,
            kategorie_ar TEXT NOT NULL,
            kategorie_de TEXT NOT NULL,
            beschreibung_ar TEXT NOT NULL,
            beschreibung_de TEXT NOT NULL,
            betrag_sar REAL NOT NULL,
            beleg TEXT,
            ohne_beleg INTEGER DEFAULT 0,
            vorschuss_eur REAL,
            genehmigt INTEGER DEFAULT 0,
            genehmigt_von TEXT,
            rejection_reason TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
        """)
        # migrations for sqlite
        if not _col_exists_sqlite(cur, "users", "wechselkurs_beleg"):
            cur.execute("ALTER TABLE users ADD COLUMN wechselkurs_beleg TEXT")
        if not _col_exists_sqlite(cur, "kosten", "ohne_beleg"):
            cur.execute("ALTER TABLE kosten ADD COLUMN ohne_beleg INTEGER DEFAULT 0")
        if not _col_exists_sqlite(cur, "kosten", "rejection_reason"):
            cur.execute("ALTER TABLE kosten ADD COLUMN rejection_reason TEXT")

    conn.commit()
    conn.close()


@app.before_request
def _before():
    ensure_schema()


# =====================
# Helpers (auth / role)
# =====================
def current_user():
    if "user_id" not in session:
        return None
    return {
        "id": session.get("user_id"),
        "username": session.get("username"),
        "role": session.get("role"),
    }


def require_login():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return None


def require_role(role: str):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != role:
        abort(403)
    return None


def _save_upload(file_storage) -> str | None:
    if not file_storage or not getattr(file_storage, "filename", ""):
        return None
    filename = secure_filename(file_storage.filename)
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_UPLOAD_EXT:
        raise ValueError("Ungültiges Dateiformat")
    safe_name = f"{uuid.uuid4().hex}{ext}"
    file_storage.save(str(UPLOAD_DIR / safe_name))
    return safe_name


def _cat_obj(code: str):
    return CATEGORIES.get(code) or {"de": code, "ar": code}


def _ordered_categories():
    # ensure all keys are present once
    keys = []
    seen = set()
    for k in CATEGORY_ORDER + list(CATEGORIES.keys()):
        if k in CATEGORIES and k not in seen:
            keys.append(k)
            seen.add(k)
    return [(k, CATEGORIES[k]) for k in keys]


# =====================
# Static / uploads
# =====================
@app.route("/uploads/<path:filename>")
def uploads(filename):
    # basic hardening: no directory traversal
    if ".." in filename or filename.startswith("/"):
        abort(400)
    return send_from_directory(str(UPLOAD_DIR), filename, as_attachment=False)


# =====================
# Auth
# =====================
@app.route("/")
def index():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard") if u["role"] == "reisefuehrer" else url_for("admin"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        role = request.form.get("role") or "reisefuehrer"
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""

        if not username or not password:
            flash("Bitte alle Felder ausfüllen.", "err")
            return redirect(url_for("register"))
        if password != password2:
            flash("Passwörter stimmen nicht überein.", "err")
            return redirect(url_for("register"))
        if role not in ("reisefuehrer", "buchhaltung"):
            role = "reisefuehrer"

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)"
                if DATABASE_URL else
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, generate_password_hash(password), role)
            )
            conn.commit()
            flash("Registrierung erfolgreich. Bitte einloggen.", "ok")
            return redirect(url_for("login"))
        except Exception:
            conn.rollback()
            flash("Username existiert bereits oder Eingabe ungültig.", "err")
            return redirect(url_for("register"))
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM users WHERE username=%s" if DATABASE_URL else "SELECT * FROM users WHERE username=?",
            (username,)
        )
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("index"))

        flash("Login fehlgeschlagen.", "err")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =====================
# Reiseführer Dashboard
# =====================
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    guard = require_role("reisefuehrer")
    if guard:
        return guard

    user_id = session["user_id"]

    conn = get_db()
    cur = conn.cursor()

    # Handle POST actions
    if request.method == "POST":
        action = request.form.get("action") or "add_kosten"

        if action == "set_start":
            start_str = (request.form.get("startguthaben_sar") or "0").replace(",", ".").strip()
            try:
                start_val = float(start_str)
                if start_val < 0:
                    raise ValueError()
            except Exception:
                flash("Bitte ein gültiges Startguthaben eingeben.", "err")
                conn.close()
                return redirect(url_for("dashboard"))

            # optional: exchange-rate receipt upload (not required)
            try:
                receipt = _save_upload(request.files.get("wechselkurs_beleg"))
            except Exception:
                receipt = None

            cur.execute(
                "UPDATE users SET startguthaben_sar=%s, wechselkurs_beleg=COALESCE(%s, wechselkurs_beleg) WHERE id=%s"
                if DATABASE_URL else
                "UPDATE users SET startguthaben_sar=?, wechselkurs_beleg=COALESCE(?, wechselkurs_beleg) WHERE id=?",
                (start_val, receipt, user_id)
            )
            conn.commit()
            flash("Startguthaben gespeichert.", "ok")
            conn.close()
            return redirect(url_for("dashboard"))

        if action == "reset_start":
            cur.execute(
                "UPDATE users SET startguthaben_sar=%s WHERE id=%s"
                if DATABASE_URL else
                "UPDATE users SET startguthaben_sar=? WHERE id=?",
                (0, user_id)
            )
            conn.commit()
            flash("Startguthaben zurückgesetzt.", "ok")
            conn.close()
            return redirect(url_for("dashboard"))

        if action == "delete_kosten":
            kid = request.form.get("kid")
            try:
                kid_i = int(kid)
            except Exception:
                flash("Ungültige ID.", "err")
                conn.close()
                return redirect(url_for("dashboard"))

            # Nur pending (genehmigt=0) darf gelöscht werden
            cur.execute(
                "DELETE FROM kosten WHERE id=%s AND user_id=%s AND genehmigt=0"
                if DATABASE_URL else
                "DELETE FROM kosten WHERE id=? AND user_id=? AND genehmigt=0",
                (kid_i, user_id)
            )
            conn.commit()
            flash("Ausgabe gelöscht.", "ok")
            conn.close()
            return redirect(url_for("dashboard"))

        # default: add expense
        datum = request.form.get("datum") or datetime.now().strftime("%Y-%m-%d")
        kategorie_code = request.form.get("kategorie") or "OTHER"
        beschreibung_ar = (request.form.get("beschreibung_ar") or "").strip()
        beschreibung_de = (request.form.get("beschreibung_de") or "").strip()
        betrag_str = (request.form.get("betrag_sar") or "0").replace(",", ".").strip()

        ohne_beleg = True if request.form.get("ohne_beleg") else False
        file_obj = request.files.get("beleg")

        # Pflicht: Entweder Beleg ODER "ohne Beleg"
        if (not ohne_beleg) and (not file_obj or not file_obj.filename):
            flash("Bitte entweder einen Beleg hochladen ODER „ohne Beleg“ auswählen.", "err")
            conn.close()
            return redirect(url_for("dashboard"))
        if ohne_beleg and file_obj and file_obj.filename:
            # Beide gewählt -> ok, wir akzeptieren den Beleg trotzdem, aber setzen ohne_beleg auf 0
            ohne_beleg = False

        try:
            betrag = float(betrag_str)
            if betrag <= 0:
                raise ValueError()
        except Exception:
            flash("Bitte einen gültigen Betrag (> 0) eingeben.", "err")
            conn.close()
            return redirect(url_for("dashboard"))

        cat = _cat_obj(kategorie_code)
        kategorie_ar = cat["ar"]
        kategorie_de = cat["de"]

        beleg_name = None
        if not ohne_beleg:
            try:
                beleg_name = _save_upload(file_obj)
            except Exception as e:
                flash(f"Upload fehlgeschlagen: {e}", "err")
                conn.close()
                return redirect(url_for("dashboard"))

        cur.execute(
            """
            INSERT INTO kosten
            (user_id, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de,
             betrag_sar, beleg, ohne_beleg, genehmigt)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,0)
            """ if DATABASE_URL else
            """
            INSERT INTO kosten
            (user_id, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de,
             betrag_sar, beleg, ohne_beleg, genehmigt)
            VALUES (?,?,?,?,?,?,?,?,?,0)
            """,
            (user_id, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de,
             betrag, beleg_name, (True if DATABASE_URL else (1 if ohne_beleg else 0)))
        )
        conn.commit()
        flash("Ausgabe gespeichert (wartet auf Buchhaltung).", "ok")
        conn.close()
        return redirect(url_for("dashboard"))

    # GET: show overview
    cur.execute(
        "SELECT startguthaben_sar, wechselkurs_beleg FROM users WHERE id=%s"
        if DATABASE_URL else
        "SELECT startguthaben_sar, wechselkurs_beleg FROM users WHERE id=?",
        (user_id,)
    )
    u = cur.fetchone()
    start = float(u["startguthaben_sar"] or 0)
    wechselkurs_beleg = u["wechselkurs_beleg"]

    # total "gebunden" = approved + pending, rejected wird NICHT gezählt
    cur.execute(
        "SELECT COALESCE(SUM(betrag_sar),0) AS s FROM kosten WHERE user_id=%s AND genehmigt!=-1"
        if DATABASE_URL else
        "SELECT COALESCE(SUM(betrag_sar),0) AS s FROM kosten WHERE user_id=? AND genehmigt!=-1",
        (user_id,)
    )
    total = float(cur.fetchone()["s"] or 0)

    saldo = start - total

    cur.execute(
        "SELECT * FROM kosten WHERE user_id=%s ORDER BY id DESC" if DATABASE_URL else
        "SELECT * FROM kosten WHERE user_id=? ORDER BY id DESC",
        (user_id,)
    )
    rows = cur.fetchall()
    conn.close()

    today = datetime.now().strftime("%Y-%m-%d")
    ordered = _ordered_categories()

    return render_template(
        "dashboard.html",
        start=start,
        total=total,
        saldo=saldo,
        rows=rows,
        today=today,
        ordered=ordered,
        wechselkurs_beleg=wechselkurs_beleg
    )


# =====================
# Buchhaltung (Admin)
# =====================
@app.route("/admin")
def admin():
    guard = require_role("buchhaltung")
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()

    # Gesamtübersicht (Requirement #3)
    cur.execute(
        "SELECT COALESCE(SUM(startguthaben_sar),0) AS s FROM users WHERE role=%s"
        if DATABASE_URL else
        "SELECT COALESCE(SUM(startguthaben_sar),0) AS s FROM users WHERE role=?",
        ("reisefuehrer",)
    )
    total_start = float(cur.fetchone()["s"] or 0)

    cur.execute(
        """
        SELECT COALESCE(SUM(k.betrag_sar),0) AS s
        FROM kosten k
        JOIN users u ON u.id = k.user_id
        WHERE u.role=%s AND k.genehmigt!=-1
        """ if DATABASE_URL else
        """
        SELECT COALESCE(SUM(k.betrag_sar),0) AS s
        FROM kosten k
        JOIN users u ON u.id = k.user_id
        WHERE u.role=? AND k.genehmigt!=-1
        """,
        ("reisefuehrer",)
    )
    total_spent = float(cur.fetchone()["s"] or 0)
    total_rest = total_start - total_spent

    # Alle Kosten (meistens relevant: pending zuerst)
    cur.execute(
        """
        SELECT k.*, u.username
        FROM kosten k
        JOIN users u ON u.id = k.user_id
        ORDER BY k.genehmigt ASC, k.id DESC
        """ if DATABASE_URL else
        """
        SELECT k.*, u.username
        FROM kosten k
        JOIN users u ON u.id = k.user_id
        ORDER BY k.genehmigt ASC, k.id DESC
        """
    )
    kosten = cur.fetchall()
    conn.close()

    return render_template(
        "admin.html",
        kosten=kosten,
        total_start=total_start,
        total_spent=total_spent,
        total_rest=total_rest
    )


@app.route("/genehmigen/<int:kid>")
def genehmigen(kid: int):
    guard = require_role("buchhaltung")
    if guard:
        return guard

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE kosten SET genehmigt=1, genehmigt_von=%s, rejection_reason=NULL WHERE id=%s"
        if DATABASE_URL else
        "UPDATE kosten SET genehmigt=1, genehmigt_von=?, rejection_reason=NULL WHERE id=?",
        (session.get("username"), kid)
    )
    conn.commit()
    conn.close()
    flash("Ausgabe genehmigt.", "ok")
    return redirect(url_for("admin"))


@app.route("/ablehnen/<int:kid>", methods=["GET", "POST"])
def ablehnen(kid: int):
    guard = require_role("buchhaltung")
    if guard:
        return guard

    if request.method == "POST":
        reason = (request.form.get("reason") or "").strip()
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "UPDATE kosten SET genehmigt=-1, genehmigt_von=%s, rejection_reason=%s WHERE id=%s"
            if DATABASE_URL else
            "UPDATE kosten SET genehmigt=-1, genehmigt_von=?, rejection_reason=? WHERE id=?",
            (session.get("username"), reason, kid)
        )
        conn.commit()
        conn.close()
        flash("Ausgabe abgelehnt – Betrag wurde dem Guthaben wieder hinzugefügt.", "ok")
        return redirect(url_for("admin"))

    # GET simple form
    return render_template("reject.html", kid=kid)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
