import os
import sqlite3
import uuid
import hashlib
import smtplib
import io
import csv
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import psycopg2
import psycopg2.extras

# =====================
# Flask App
# =====================

# =====================
# Kategorien (Keys -> Sprachen)
# =====================
CATEGORIES = {
    "meal": {"ar": "وجبات", "de": "Verpflegung"},
    "hotel": {"ar": "فندق", "de": "Hotel"},
    "transport": {"ar": "مواصلات", "de": "Transport"},
    "shopping": {"ar": "تسوق", "de": "Einkauf"},
    "other": {"ar": "أخرى", "de": "Sonstiges"},
    "taxi": {"ar": "تاكسي", "de": "Taxi"},
    "tip_bus": {"ar": "إكرامية سائق الحافلة", "de": "Trinkgeld Busfahrer"},
    "tip_hotel": {"ar": "إكرامية موظفي الفندق", "de": "Trinkgeld Hotelmitarbeiter"},
}
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")


# Uploads
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# =====================
# Database
# =====================
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    if DATABASE_URL:
        conn = psycopg2.connect(
            DATABASE_URL,
            connect_timeout=5,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        return conn
    else:
        conn = sqlite3.connect(
            "reisekosten.db",
            timeout=10,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

def ensure_schema():
    conn = get_db()
    cur = conn.cursor()

    # ---- users ----
    if DATABASE_URL:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT,
            email TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,
            reset_token TEXT,
            reset_expires TIMESTAMP
        )
        """)
    else:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,
            reset_token TEXT,
            reset_expires TEXT
        )
        """)

    # ---- startguthaben ----
    if DATABASE_URL:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS startguthaben (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            betrag_sar NUMERIC NOT NULL DEFAULT 0,
            wechselkurs_beleg TEXT
        )
        """)
    else:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS startguthaben (
            user_id INTEGER PRIMARY KEY,
            betrag_sar REAL NOT NULL DEFAULT 0,
            wechselkurs_beleg TEXT
        )
        """)

    # ---- kosten ----
    if DATABASE_URL:
        cur.execute("""
    CREATE TABLE IF NOT EXISTS kosten (
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER,
        datum DATE,
        kategorie_ar TEXT,
        kategorie_de TEXT NOT NULL DEFAULT '',
        beschreibung_ar TEXT,
        beschreibung_de TEXT NOT NULL DEFAULT '',
        betrag_sar NUMERIC NOT NULL DEFAULT 0,
        beleg TEXT,
        ohne_beleg INTEGER NOT NULL DEFAULT 0,
        genehmigt INTEGER NOT NULL DEFAULT 0,
        genehmigt_von TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
""")
    else:
        cur.execute("""
    CREATE TABLE IF NOT EXISTS kosten (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        datum TEXT,
        kategorie_ar TEXT,
        kategorie_de TEXT NOT NULL DEFAULT '',
        beschreibung_ar TEXT,
        beschreibung_de TEXT NOT NULL DEFAULT '',
        betrag_sar REAL NOT NULL DEFAULT 0,
        beleg TEXT,
        ohne_beleg INTEGER NOT NULL DEFAULT 0,
        genehmigt INTEGER NOT NULL DEFAULT 0,
        genehmigt_von TEXT,
        created_at TEXT
    )
""")


    # ---- migration: hide entries from Buchhaltung without deleting for Reiseführer ----
    # Add buchhaltung_deleted column if missing
    try:
        if DATABASE_URL:
            cur.execute("ALTER TABLE kosten ADD COLUMN buchhaltung_deleted INTEGER NOT NULL DEFAULT 0")
        else:
            cur.execute("ALTER TABLE kosten ADD COLUMN buchhaltung_deleted INTEGER NOT NULL DEFAULT 0")
    except Exception:
        # column probably already exists
        pass

    conn.commit()
    conn.close()


# =====================
# DB schema init (Render-safe)
# =====================
_SCHEMA_READY = False

@app.before_request
def _ensure_schema_once():
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    try:
        ensure_schema()
        _SCHEMA_READY = True
    except Exception as e:
        # Don't hard-crash the whole process on boot; surface in logs
        print("DB schema init failed:", repr(e), flush=True)
        raise


# =====================
# SMTP – STRATO
# =====================
def send_reset_email(to_email, reset_link):
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", 587))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    from_email = os.environ.get("SMTP_FROM")

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = "Passwort zurücksetzen"

    body = f"""
Hallo,

du kannst dein Passwort über folgenden Link zurücksetzen:

{reset_link}

Der Link ist 30 Minuten gültig.

Falls du das nicht warst, ignoriere diese E-Mail.
"""
    msg.attach(MIMEText(body, "plain", "utf-8"))

    print("SMTP: connecting")
    server = smtplib.SMTP(host, port, timeout=10)
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(user, password)
    server.sendmail(from_email, [to_email], msg.as_string())
    server.quit()
    print("SMTP: mail sent")



# =====================
# Routes
# =====================
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    # role only for UI selection / highlighting
    selected_role = request.args.get("role", "reisefuehrer")

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Bitte E-Mail und Passwort eingeben")
            return redirect(url_for("login", role=selected_role))

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, email, password_hash, role FROM users WHERE email = %s"
            if DATABASE_URL else
            "SELECT id, username, email, password_hash, role FROM users WHERE email = ?",
            (email,)
        )
        user = cur.fetchone()
        conn.close()

        if user:
            # robust for sqlite tuple/Row and postgres dict
            pw_hash = user["password_hash"] if hasattr(user, "keys") else user[3]
            if pw_hash and check_password_hash(pw_hash, password):
                session["user_id"] = user["id"] if hasattr(user, "keys") else user[0]
                session["role"] = user["role"] if hasattr(user, "keys") else user[4]
                session["username"] = user["username"] if hasattr(user, "keys") else user[1]
                return redirect(url_for("dashboard"))

        flash("Login fehlgeschlagen")
        return redirect(url_for("login", role=selected_role))

    return render_template("login.html", role=selected_role)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role", "reisefuehrer")

        if not username or not email or not password:
            flash("Bitte alle Felder ausfüllen")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT id FROM users WHERE email = %s"
            if DATABASE_URL else
            "SELECT id FROM users WHERE email = ?",
            (email,)
        )
        exists = cur.fetchone()
        conn.close()

        if exists:
            flash("E-Mail ist bereits registriert")
            return redirect(url_for("register"))

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (%s,%s,%s,%s)"
                if DATABASE_URL else
                "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
                (username, email, pw_hash, role)
            )
            conn.commit()
        finally:
            conn.close()

        flash("Registrierung erfolgreich – bitte einloggen")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    print("FORGOT ROUTE AUFGERUFEN")

    if request.method == "POST":
        email = request.form.get("email")
        print("E-MAIL AUS FORMULAR:", email)

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM users WHERE email = %s" if DATABASE_URL else
            "SELECT * FROM users WHERE email = ?", (email,)
        )
        user = cur.fetchone()

        print("USER AUS DB:", user)

        if user:
            print("USER GEFUNDEN – TOKEN + MAIL")

            token = uuid.uuid4().hex
            expires = datetime.utcnow() + timedelta(minutes=30)

            cur.execute(
                "UPDATE users SET reset_token=%s, reset_expires=%s WHERE id=%s"
                if DATABASE_URL else
                "UPDATE users SET reset_token=?, reset_expires=? WHERE id=?",
                (token, expires, user["id"])
            )
            conn.commit()

            base_url = os.environ.get("RESET_BASE_URL", "http://localhost:5000")
            reset_link = f"{base_url}/reset/{token}"
            print("RESET LINK:", reset_link)

            send_reset_email(user["email"], reset_link)
            print("SEND_RESET_EMAIL AUFGERUFEN")

        else:
            print("KEIN USER MIT DIESER E-MAIL")

        conn.close()
        flash("Wenn die E-Mail existiert, wurde eine Nachricht versendet.")
        return redirect(url_for("login"))

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM users WHERE reset_token=%s"
        if DATABASE_URL else
        "SELECT * FROM users WHERE reset_token=?",
        (token,)
    )
    user = cur.fetchone()

    if not user:
        conn.close()
        flash("Ungültiger oder abgelaufener Link")
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form["password"]
        pw_hash = generate_password_hash(password)

        cur.execute(
            "UPDATE users SET password_hash=%s, reset_token=NULL, reset_expires=NULL WHERE id=%s"
            if DATABASE_URL else
            "UPDATE users SET password_hash=?, reset_token=NULL, reset_expires=NULL WHERE id=?",
            (pw_hash, user["id"])
        )
        conn.commit()
        conn.close()

        flash("Passwort erfolgreich geändert")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset.html")

@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

def _parse_decimal(val: str) -> float:
    if val is None:
        return 0.0
    val = val.strip().replace(",", ".")
    try:
        return float(val)
    except ValueError:
        return 0.0

def _now_iso():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    role = session.get("role", "reisefuehrer")
    uid = session["user_id"]

    # =========================
    # Buchhaltung
    # =========================
    if role == "buchhaltung":
        if request.method == "POST":
            action = request.form.get("action")
            kid = request.form.get("kid")

            # NEU: Eintrag nur aus der Buchhaltungs-Ansicht entfernen (bleibt beim Reiseführer sichtbar)
            if action == "delete":
                if not kid:
                    return redirect(url_for("dashboard"))

                conn = get_db()
                cur = conn.cursor()

                # Datensatz laden (für Rückbuchung)
                if DATABASE_URL:
                    cur.execute("SELECT user_id, betrag_sar FROM kosten WHERE id=%s", (kid,))
                else:
                    cur.execute("SELECT user_id, betrag_sar FROM kosten WHERE id=?", (kid,))

                row = cur.fetchone()
                if not row:
                    conn.close()
                    flash("Eintrag nicht gefunden", "err")
                    return redirect(url_for("dashboard"))

                if hasattr(row, "keys"):
                    reisefuehrer_id = row["user_id"]
                    betrag = float(row["betrag_sar"] or 0)
                else:
                    reisefuehrer_id = row[0]
                    betrag = float(row[1] or 0)

                # Rückbuchung ins Startguthaben (Upsert)
                if DATABASE_URL:
                    cur.execute(
                        """
                        INSERT INTO startguthaben (user_id, betrag_sar)
                        VALUES (%s, %s)
                        ON CONFLICT (user_id) DO UPDATE
                        SET betrag_sar = startguthaben.betrag_sar + EXCLUDED.betrag_sar
                        """,
                        (reisefuehrer_id, betrag)
                    )
                else:
                    cur.execute(
                        "INSERT OR IGNORE INTO startguthaben (user_id, betrag_sar) VALUES (?,0)",
                        (reisefuehrer_id,)
                    )
                    cur.execute(
                        "UPDATE startguthaben SET betrag_sar = betrag_sar + ? WHERE user_id=?",
                        (betrag, reisefuehrer_id)
                    )

                # Eintrag endgültig löschen (auch alte SQLite-Einträge)
                if DATABASE_URL:
                    cur.execute("DELETE FROM kosten WHERE id=%s", (kid,))
                else:
                    cur.execute("DELETE FROM kosten WHERE id=?", (kid,))

                conn.commit()
                conn.close()
                flash("Eintrag gelöscht & Betrag zurückgebucht", "ok")
                return redirect(url_for("dashboard"))

            if action in ("approve", "deny"):
                if not kid:
                    return redirect(url_for("dashboard"))

                conn = get_db()
                cur = conn.cursor()
                genehmigt_val = 1 if action == "approve" else -1

                # Datensatz laden, um Rückbuchung korrekt zu machen
                if DATABASE_URL:
                    cur.execute("SELECT user_id, betrag_sar, genehmigt FROM kosten WHERE id=%s", (kid,))
                else:
                    cur.execute("SELECT user_id, betrag_sar, genehmigt FROM kosten WHERE id=?", (kid,))

                row = cur.fetchone()
                if not row:
                    conn.close()
                    return redirect(url_for("dashboard"))

                if hasattr(row, "keys"):
                    reisefuehrer_id = row["user_id"]
                    betrag = float(row["betrag_sar"] or 0)
                    alt_status = int(row["genehmigt"] or 0)
                else:
                    reisefuehrer_id = row[0]
                    betrag = float(row[1] or 0)
                    alt_status = int(row[2] or 0)

                # Status aktualisieren
                if DATABASE_URL:
                    cur.execute(
                        "UPDATE kosten SET genehmigt=%s, genehmigt_von=%s WHERE id=%s",
                        (genehmigt_val, session.get("username", ""), kid)
                    )
                else:
                    cur.execute(
                        "UPDATE kosten SET genehmigt=?, genehmigt_von=? WHERE id=?",
                        (genehmigt_val, session.get("username", ""), kid)
                    )

                # Rückbuchung nur bei Ablehnung (und nur einmal)
                if genehmigt_val == -1 and alt_status != -1:
                    if DATABASE_URL:
                        cur.execute(
                            "UPDATE startguthaben SET betrag_sar = betrag_sar + %s WHERE user_id=%s",
                            (betrag, reisefuehrer_id)
                        )
                    else:
                        cur.execute(
                            "UPDATE users SET startguthaben = startguthaben + ? WHERE id=?",
                            (betrag, reisefuehrer_id)
                        )

                # Korrektur: falls vorher abgelehnt und jetzt genehmigt
                if alt_status == -1 and genehmigt_val == 1:
                    if DATABASE_URL:
                        cur.execute(
                            "UPDATE users SET startguthaben = startguthaben - %s WHERE id=%s",
                            (betrag, reisefuehrer_id)
                        )
                    else:
                        cur.execute(
                            "UPDATE users SET startguthaben = startguthaben - ? WHERE id=?",
                            (betrag, reisefuehrer_id)
                        )

                conn.commit()
                conn.close()
                flash("Status aktualisiert", "ok")
                return redirect(url_for("dashboard"))

                conn = get_db()
                cur = conn.cursor()
                genehmigt_val = 1 if action == "approve" else -1

                # Datensatz laden, um Rückbuchung korrekt zu machen
                if DATABASE_URL:
                        cur.execute("SELECT user_id, betrag_sar, genehmigt FROM kosten WHERE id=%s", (kid,))
                else:
                        cur.execute("SELECT user_id, betrag_sar, genehmigt FROM kosten WHERE id=?", (kid,))

                row = cur.fetchone()
                if not row:
                        conn.close()
                        return redirect(url_for("dashboard"))

                if hasattr(row, "keys"):
                        reisefuehrer_id = row["user_id"]
                        betrag = float(row["betrag_sar"] or 0)
                        alt_status = int(row["genehmigt"] or 0)
                else:
                        reisefuehrer_id = row[0]
                        betrag = float(row[1] or 0)
                        alt_status = int(row[2] or 0)

                # Status aktualisieren (ohne Zeitstempel-Spalte)
                if DATABASE_URL:
                        cur.execute(
                            "UPDATE kosten SET genehmigt=%s, genehmigt_von=%s WHERE id=%s",
                            (genehmigt_val, session.get("username", ""), kid)
                        )
                else:
                        cur.execute(
                            "UPDATE kosten SET genehmigt=?, genehmigt_von=? WHERE id=?",
                            (genehmigt_val, session.get("username", ""), kid)
                        )

                # Rückbuchung nur bei Ablehnung (und nur einmal)
                if genehmigt_val == -1 and alt_status != -1:
                        if DATABASE_URL:
                            cur.execute(
                                "UPDATE users SET startguthaben = startguthaben + %s WHERE id=%s",
                                (betrag, reisefuehrer_id)
                            )
                        else:
                            cur.execute(
                                "UPDATE users SET startguthaben = startguthaben + ? WHERE id=?",
                                (betrag, reisefuehrer_id)
                            )

                # Korrektur: falls vorher abgelehnt und jetzt genehmigt -> Rückbuchung wieder abziehen
                if alt_status == -1 and genehmigt_val == 1:
                        if DATABASE_URL:
                            cur.execute(
                                "UPDATE startguthaben SET betrag_sar = betrag_sar - %s WHERE user_id=%s",
                                (betrag, reisefuehrer_id)
                            )
                        else:
                            cur.execute(
                                "UPDATE users SET startguthaben = startguthaben - ? WHERE id=?",
                                (betrag, reisefuehrer_id)
                            )

                conn.commit()
                conn.close()
                flash("Status aktualisiert", "ok")
                return redirect(url_for("dashboard"))


        # GET: Buchhaltung-Übersicht
        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT id, username FROM users WHERE role = %s" if DATABASE_URL else
            "SELECT id, username FROM users WHERE role = ?",
            ("reisefuehrer",)
        )
        users = cur.fetchall() or []

        users_summary = []
        for u in users:
            u_id = u["id"] if hasattr(u, "keys") else u[0]
            u_name = u["username"] if hasattr(u, "keys") else u[1]

            # start
            cur.execute(
                "SELECT betrag_sar FROM startguthaben WHERE user_id=%s" if DATABASE_URL else
                "SELECT betrag_sar FROM startguthaben WHERE user_id=?",
                (u_id,)
            )
            r0 = cur.fetchone()
            start = float(r0.get("betrag_sar", 0) if hasattr(r0, "keys") else (r0[0] if r0 else 0.0)) if r0 else 0.0

            # total (pending + approved), rejected excluded
            cur.execute(
                "SELECT COALESCE(SUM(betrag_sar),0) AS total FROM kosten WHERE user_id=%s AND genehmigt<>-1" if DATABASE_URL else
                "SELECT COALESCE(SUM(betrag_sar),0) FROM kosten WHERE user_id=? AND genehmigt<>-1",
                (u_id,)
            )
            r1 = cur.fetchone()
            total = float(r1.get("total", 0) if hasattr(r1, "keys") else (r1[0] if r1 else 0.0)) if r1 else 0.0

            users_summary.append({"username": u_name, "start": start, "total": total, "saldo": start - total})

        # all costs
        cur.execute(
            """
            SELECT k.id, k.user_id, u.username, k.datum, k.kategorie_ar, k.beschreibung_ar, k.betrag_sar,
                   k.beleg, k.genehmigt, k.genehmigt_von
            FROM kosten k
            JOIN users u ON u.id = k.user_id
            WHERE COALESCE(k.buchhaltung_deleted,0)=0
            ORDER BY k.id DESC
            """
        )
        kosten = []
        for row in (cur.fetchall() or []):
            r = dict(row) if hasattr(row, "keys") else {
                "id": row[0], "user_id": row[1], "username": row[2], "datum": row[3], "kategorie_ar": row[4],
                "beschreibung_ar": row[5], "betrag_sar": row[6], "beleg": row[7], "genehmigt": row[8], "genehmigt_von": row[9]
            }

            kosten.append(r)

        conn.close()
        return render_template("admin.html", users_summary=users_summary, kosten=kosten)

    # =========================
    # Reiseführer
    # =========================
    if request.method == "POST":
        action = request.form.get("action")
        conn = get_db()
        cur = conn.cursor()

        if action == "set_start":
            betrag = _parse_decimal(request.form.get("startguthaben_sar", "0"))
            wechselkurs_beleg = None

            file = request.files.get("wechselkurs_beleg")
            if file and file.filename:
                fname = secure_filename(file.filename)
                wechselkurs_beleg = f"{uuid.uuid4().hex}_{fname}"
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], wechselkurs_beleg))

            if DATABASE_URL:
                cur.execute(
                """
                INSERT INTO startguthaben (user_id, betrag_sar, wechselkurs_beleg)
                VALUES (%s,%s,%s)
                ON CONFLICT (user_id) DO UPDATE SET
                      betrag_sar=EXCLUDED.betrag_sar,
                      wechselkurs_beleg=COALESCE(EXCLUDED.wechselkurs_beleg, startguthaben.wechselkurs_beleg)
                """,
                (uid, betrag, wechselkurs_beleg)
                )
            else:
                cur.execute("SELECT wechselkurs_beleg FROM startguthaben WHERE user_id=?", (uid,))
                existing = cur.fetchone()
                existing_beleg = existing.get("wechselkurs_beleg") if hasattr(existing, "keys") else (existing[0] if existing else None)
                cur.execute(
                "INSERT OR REPLACE INTO startguthaben (user_id, betrag_sar, wechselkurs_beleg) VALUES (?,?,?)",
                (uid, betrag, wechselkurs_beleg or existing_beleg)
                )

            conn.commit()
            conn.close()
            flash("Startguthaben gespeichert", "ok")
            return redirect(url_for("dashboard"))

        if action == "reset_start":
            if DATABASE_URL:
                cur.execute("DELETE FROM startguthaben WHERE user_id=%s", (uid,))
            else:
                cur.execute("DELETE FROM startguthaben WHERE user_id=?", (uid,))
            conn.commit()
            conn.close()
            flash("Startguthaben zurückgesetzt", "ok")
            return redirect(url_for("dashboard"))

        if action == "add_kosten":
            datum = request.form.get("datum")
            kategorie_ar = request.form.get("kategorie")
            kategorie_de = CATEGORIES.get(kategorie_ar, {}).get("de")
            beschreibung_ar = request.form.get("beschreibung_ar")
            beschreibung_de = beschreibung_ar
            betrag = _parse_decimal(request.form.get("betrag_sar", "0"))
            
            if DATABASE_URL:
                ohne_beleg = True if request.form.get("ohne_beleg") else False
            else:
                ohne_beleg = 1 if request.form.get("ohne_beleg") else 0


            beleg_filename = None
            beleg_file = request.files.get("beleg")
            if beleg_file and beleg_file.filename:
                fname = secure_filename(beleg_file.filename)
                beleg_filename = f"{uuid.uuid4().hex}_{fname}"
                beleg_file.save(os.path.join(app.config["UPLOAD_FOLDER"], beleg_filename))

            if ohne_beleg == 0 and not beleg_filename:
                conn.close()
                flash("Bitte Beleg hochladen oder 'بدون إيصال' aktivieren.", "err")
                return redirect(url_for("dashboard"))

            if DATABASE_URL:
                cur.execute(
                """
                INSERT INTO kosten (
                        user_id, datum,
                        kategorie_ar, kategorie_de,
                        beschreibung_ar, beschreibung_de,
                        betrag_sar, beleg, ohne_beleg,
                        genehmigt, created_at
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,0,NOW())
                """,
                (uid, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de, betrag, beleg_filename, ohne_beleg)
                )
            else:
                cur.execute(
                """
                INSERT INTO kosten (
                        user_id, datum,
                        kategorie_ar, kategorie_de,
                        beschreibung_ar, beschreibung_de,
                        betrag_sar, beleg, ohne_beleg,
                        genehmigt, created_at
                )
                VALUES (?,?,?,?,?,?,?,?,?,0,?)
                """,
                (uid, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de, betrag, beleg_filename, ohne_beleg, _now_iso())
                )

            conn.commit()
            conn.close()
            flash("Ausgabe gespeichert", "ok")
            return redirect(url_for("dashboard"))

        if action == "delete_kosten":
            kid = request.form.get("kid")
            if kid:
                if DATABASE_URL:
                    cur.execute(
                        "DELETE FROM kosten WHERE id=%s AND user_id=%s AND genehmigt=0",
                        (kid, uid)
                    )
                else:
                    cur.execute(
                        "DELETE FROM kosten WHERE id=? AND user_id=? AND genehmigt=0",
                        (kid, uid)
                    )
                conn.commit()

            conn.close()
            flash("Gelöscht", "ok")
            return redirect(url_for("dashboard"))

        conn.close()
        return redirect(url_for("dashboard"))

    # GET: Daten laden
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT betrag_sar, wechselkurs_beleg FROM startguthaben WHERE user_id=%s" if DATABASE_URL else
        "SELECT betrag_sar, wechselkurs_beleg FROM startguthaben WHERE user_id=?",
        (uid,)
    )
    r0 = cur.fetchone()
    if r0:
        start = float(r0.get("betrag_sar", 0) if hasattr(r0, "keys") else r0[0])
        wechselkurs_beleg = r0.get("wechselkurs_beleg") if hasattr(r0, "keys") else (r0[1] if len(r0) > 1 else None)
    else:
        start = 0.0
        wechselkurs_beleg = None

    cur.execute(
        "SELECT COALESCE(SUM(betrag_sar),0) AS total FROM kosten WHERE user_id=%s AND genehmigt<>-1" if DATABASE_URL else
        "SELECT COALESCE(SUM(betrag_sar),0) FROM kosten WHERE user_id=? AND genehmigt<>-1",
        (uid,)
    )
    r1 = cur.fetchone()
    total = float(r1.get("total", 0) if hasattr(r1, "keys") else (r1[0] if r1 else 0.0)) if r1 else 0.0
    saldo = start - total

    cur.execute(
        "SELECT id, datum, kategorie_ar, beschreibung_ar, betrag_sar, beleg, genehmigt FROM kosten WHERE user_id=%s ORDER BY id DESC" if DATABASE_URL else
        "SELECT id, datum, kategorie_ar, beschreibung_ar, betrag_sar, beleg, genehmigt FROM kosten WHERE user_id=? ORDER BY id DESC",
        (uid,)
    )

    rows_db = cur.fetchall() or []
    rows = []

    for r in rows_db:
        d = dict(r) if hasattr(r, "keys") else {
            "id": r[0],
            "datum": r[1],
            "kategorie_ar": r[2],    
            "beschreibung_ar": r[3],
            "betrag_sar": r[4],
            "beleg": r[5],
            "genehmigt": r[6]
        }
        rows.append(d)

    conn.close()

    return render_template(
        "dashboard.html",
        ordered=list(CATEGORIES.items()),
        today=datetime.utcnow().strftime("%Y-%m-%d"),
        start=start,
        total=total,
        saldo=saldo,
        rows=rows,
        wechselkurs_beleg=wechselkurs_beleg
    )

@app.route("/export_excel")
def export_excel():
    if session.get("role") != "buchhaltung":
        return redirect(url_for("dashboard"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT k.id, u.username, k.datum, k.kategorie_ar, k.beschreibung_ar, k.betrag_sar, k.genehmigt
        FROM kosten k
        JOIN users u ON u.id = k.user_id
        ORDER BY k.id DESC
        """
    )
    rows = cur.fetchall() or []
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Reiseführer", "Datum", "Kategorie", "Beschreibung (AR)", "Betrag (SAR)", "Status"])
    for r in rows:
        if hasattr(r, "keys"):
            writer.writerow([r.get("id"), r.get("username"), r.get("datum"), r.get("kategorie_ar"),
                             r.get("beschreibung_ar"), r.get("betrag_sar"), r.get("genehmigt")])
        else:
            writer.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6]])

    csv_bytes = output.getvalue().encode("utf-8-sig")
    return (csv_bytes, 200, {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": "attachment; filename=reisekosten_export.csv"
    })

@app.route("/logout")

def logout():
    session.clear()
    return redirect(url_for("login"))

