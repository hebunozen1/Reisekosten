from __future__ import annotations

import os
import sqlite3
import secrets
from datetime import timedelta, datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    send_from_directory, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Optional (kostenlos). Empfehlung: Python 3.11 verwenden.
import requests


app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "change-me-in-production")
app.permanent_session_lifetime = timedelta(days=14)  # "angemeldet bleiben"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB

KATEGORIEN = {
    "TRANSPORT":   {"ar": "النقل",          "de": "Transport"},
    "ZAMZAM":      {"ar": "ماء زمزم",       "de": "Zamzam Wasser"},
    "TRINKWASSER": {"ar": "مياه الشرب",     "de": "Trinkwasser"},
    "HELFER":      {"ar": "مساعد/أمتعة",    "de": "Helfer/Gepäck"},
    "VERPFLEGUNG": {"ar": "الطعام",         "de": "Verpflegung"},
    "SONSTIGES":   {"ar": "أخرى",           "de": "Sonstiges"},
    "PERSOENLICH": {"ar": "شخصي",           "de": "Persönlich"},
}
KATEGORIEN_ORDER = ["TRANSPORT","ZAMZAM","TRINKWASSER","HELFER","VERPFLEGUNG","SONSTIGES","PERSOENLICH"]


def get_db() -> sqlite3.Connection:
    con = sqlite3.connect("reisekosten.db")
    con.row_factory = sqlite3.Row
    return con


def ensure_schema() -> None:
    db = get_db()

    # Base schema (new installs)
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('reisefuehrer','buchhaltung')),
        startguthaben_sar REAL DEFAULT 0,
        wechselkurs_beleg TEXT,
        reset_token TEXT,
        reset_token_expires TEXT
    )
    """)
    db.execute("""
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
        vorschuss_eur REAL,
        genehmigt INTEGER DEFAULT 0,
        genehmigt_von TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )
    """)

    # Migration for existing DBs (safe)
    def _col_exists(table: str, col: str) -> bool:
        cols = db.execute(f"PRAGMA table_info({table})").fetchall()
        return any(c["name"] == col for c in cols)

    if not _col_exists("users", "email"):
        db.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if not _col_exists("users", "wechselkurs_beleg"):
        db.execute("ALTER TABLE users ADD COLUMN wechselkurs_beleg TEXT")
    if not _col_exists("users", "reset_token"):
        db.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
    if not _col_exists("users", "reset_token_expires"):
        db.execute("ALTER TABLE users ADD COLUMN reset_token_expires TEXT")

    # Default Buchhaltung user (for demo)
    row = db.execute("SELECT 1 FROM users WHERE role='buchhaltung' LIMIT 1").fetchone()
    if not row:
        db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
            ("alaa", "alaa@example.com", generate_password_hash("alaa123"), "buchhaltung"),
        )

    db.commit()
    db.close()


@app.before_request
def _init():
    ensure_schema()


def login_required(role: str | None = None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login", role="reisefuehrer"))
            if role and session.get("role") != role:
                return "Zugriff verweigert", 403
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def translate_ar_to_de(text: str) -> str:
    if not text:
        return ""

    try:
        response = requests.post(
            "https://libretranslate.de/translate",
            timeout=5,
            json={
                "q": text,
                "source": "ar",
                "target": "de",
                "format": "text"
            }
        )

        if response.status_code == 200:
            data = response.json()
            return data.get("translatedText", text)

        return text

    except Exception:
        # Fallback: Originaltext zurückgeben
        return text



@app.route("/")
def root():
    if "user_id" not in session:
        return redirect(url_for("login", role="reisefuehrer"))
    return redirect(url_for("admin" if session.get("role") == "buchhaltung" else "dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    role = request.args.get("role", "reisefuehrer")
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", role).strip().lower()
        remember = request.form.get("remember") == "on"

        if role not in ("reisefuehrer", "buchhaltung"):
            role = "reisefuehrer"

        if not email or not password:
            flash("Bitte E-Mail und Passwort eingeben.", "error")
            return render_template("login.html", role=role)

        db = get_db()
        user = db.execute(
            "SELECT id, username, email, password_hash, role FROM users WHERE email=? AND role=?",
            (email, role),
        ).fetchone()
        db.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Login fehlgeschlagen.", "error")
            return render_template("login.html", role=role)

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["email"] = user["email"]
        session["role"] = user["role"]
        session.permanent = remember  # only stay logged in when checked

        return redirect(url_for("admin" if user["role"] == "buchhaltung" else "dashboard"))

    return render_template("login.html", role=role)

@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Bitte E-Mail eingeben.", "error")
            return render_template("forgot.html")

        db = get_db()
        user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            db.close()
            flash("Wenn die E-Mail existiert, kannst du dein Passwort zurücksetzen.", "ok")
            return redirect(url_for("login"))

        token = secrets.token_urlsafe(32)
        expires = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
        db.execute("UPDATE users SET reset_token=?, reset_token_expires=? WHERE id=?", (token, expires, user["id"]))
        db.commit()
        db.close()

        # Hinweis: ohne E-Mail-Versand zeigen wir den Link direkt an.
        reset_link = url_for("reset_password", token=token, _external=True)
        flash(f"Reset-Link: {reset_link}", "ok")
        return render_template("forgot.html")

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    db = get_db()
    user = db.execute("SELECT id, reset_token_expires FROM users WHERE reset_token=?", (token,)).fetchone()
    if not user:
        db.close()
        flash("Ungültiger oder abgelaufener Link.", "error")
        return redirect(url_for("login"))

    exp = user["reset_token_expires"]
    try:
        exp_dt = datetime.fromisoformat(exp) if exp else None
    except Exception:
        exp_dt = None
    if not exp_dt or exp_dt < datetime.utcnow():
        db.execute("UPDATE users SET reset_token=NULL, reset_token_expires=NULL WHERE id=?", (user["id"],))
        db.commit()
        db.close()
        flash("Link abgelaufen.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        pw1 = request.form.get("password", "")
        pw2 = request.form.get("password2", "")
        if not pw1 or pw1 != pw2:
            flash("Passwörter stimmen nicht überein.", "error")
            db.close()
            return render_template("reset.html", token=token)

        db.execute(
            "UPDATE users SET password_hash=?, reset_token=NULL, reset_token_expires=NULL WHERE id=?",
            (generate_password_hash(pw1), user["id"]),
        )
        db.commit()
        db.close()
        flash("Passwort geändert. Bitte einloggen.", "ok")
        return redirect(url_for("login"))

    db.close()
    return render_template("reset.html", token=token)



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        role = (request.form.get("role") or "reisefuehrer").strip().lower()
        if role not in ("reisefuehrer", "buchhaltung"):
            role = "reisefuehrer"

        if not username or not email or not password:
            flash("Bitte Benutzername, E-Mail und Passwort eingeben.", "error")
            return render_template("register.html")



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login", role="reisefuehrer"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required("reisefuehrer")
def dashboard():
    db = get_db()
    uid = session["user_id"]

    if request.method == "POST":
        action = request.form.get("action", "add_kosten")

        # --- Startguthaben speichern (unabhängig von anderen Feldern) ---
        if action == "set_start":
            wert = (request.form.get("startguthaben_sar") or "").strip()
            try:
                val = float(wert.replace(",", ".")) if wert else 0.0
            except ValueError:
                flash("Bitte eine gültige Zahl für den Betrag eingeben.", "error")
                db.close()
                return redirect(url_for("dashboard"))

            # optional: Beleg Wechselkurs hochladen
            file = request.files.get("wechselkurs_beleg")
            fname = None
            if file and file.filename:
                fname = secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
                # altes File löschen (wenn vorhanden)
                old = db.execute("SELECT wechselkurs_beleg FROM users WHERE id=?", (uid,)).fetchone()
                if old and old["wechselkurs_beleg"]:
                    try:
                        os.remove(os.path.join(app.config["UPLOAD_FOLDER"], old["wechselkurs_beleg"]))
                    except Exception:
                        pass

            if fname:
                db.execute("UPDATE users SET startguthaben_sar=?, wechselkurs_beleg=? WHERE id=?", (val, fname, uid))
            else:
                db.execute("UPDATE users SET startguthaben_sar=? WHERE id=?", (val, uid))
            db.commit()
            flash("Betrag gespeichert.", "ok")
            db.close()
            return redirect(url_for("dashboard"))

        if action == "reset_start":
            # auch wechselkurs-beleg entfernen
            old = db.execute("SELECT wechselkurs_beleg FROM users WHERE id=?", (uid,)).fetchone()
            if old and old["wechselkurs_beleg"]:
                try:
                    os.remove(os.path.join(app.config["UPLOAD_FOLDER"], old["wechselkurs_beleg"]))
                except Exception:
                    pass
            db.execute("UPDATE users SET startguthaben_sar=?, wechselkurs_beleg=NULL WHERE id=?", (0.0, uid))
            db.commit()
            flash("Startguthaben wurde zurückgesetzt.", "ok")
            db.close()
            return redirect(url_for("dashboard"))

        # --- Eintrag löschen (nur wenn noch nicht genehmigt/abgelehnt) ---
        if action == "delete_kosten":
            kid_raw = (request.form.get("kid") or "").strip()
            try:
                kid = int(kid_raw)
            except ValueError:
                flash("Ungültige ID.", "error")
                db.close()
                return redirect(url_for("dashboard"))

            row = db.execute("SELECT id, beleg, genehmigt FROM kosten WHERE id=? AND user_id=?", (kid, uid)).fetchone()
            if not row:
                flash("Eintrag nicht gefunden.", "error")
                db.close()
                return redirect(url_for("dashboard"))

            if int(row["genehmigt"] or 0) != 0:
                flash("Dieser Eintrag ist bereits bearbeitet und kann nicht mehr gelöscht werden.", "error")
                db.close()
                return redirect(url_for("dashboard"))

            if row["beleg"]:
                try:
                    os.remove(os.path.join(app.config["UPLOAD_FOLDER"], row["beleg"]))
                except Exception:
                    pass

            db.execute("DELETE FROM kosten WHERE id=? AND user_id=?", (kid, uid))
            db.commit()
            flash("Eintrag gelöscht.", "ok")
            db.close()
            return redirect(url_for("dashboard"))

        # --- Ausgabe speichern ---
        datum = (request.form.get("datum") or "").strip()
        kat_code = (request.form.get("kategorie") or "").strip()
        besch_ar = (request.form.get("beschreibung_ar") or "").strip()
        betrag_sar = (request.form.get("betrag_sar") or "").strip()
        ohne_beleg = request.form.get("ohne_beleg") == "on"

        if not datum or not kat_code or not besch_ar or not betrag_sar:
            flash("Bitte alle Felder ausfüllen.", "error")
            db.close()
            return redirect(url_for("dashboard"))

        try:
            betrag_sar_f = float(betrag_sar.replace(",", "."))
        except ValueError:
            flash("Bitte eine gültige Zahl für den Betrag eingeben.", "error")
            db.close()
            return redirect(url_for("dashboard"))

        file = request.files.get("beleg")
        fname = None
        if (not ohne_beleg) and file and file.filename:
            fname = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))

        kat = KATEGORIEN.get(kat_code, {"ar": kat_code, "de": kat_code})
        besch_de = translate_ar_to_de(besch_ar)

        db.execute(
            """
            INSERT INTO kosten
            (user_id, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de, betrag_sar, beleg)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (uid, datum, kat["ar"], kat["de"], besch_ar, besch_de, betrag_sar_f, fname),
        )
        db.commit()
        flash("Ausgabe gespeichert.", "ok")
        db.close()
        return redirect(url_for("dashboard"))

    # --- Anzeige ---
    urow = db.execute("SELECT startguthaben_sar, wechselkurs_beleg FROM users WHERE id=?", (uid,)).fetchone()
    start = float(urow["startguthaben_sar"] or 0.0)
    wechselkurs_beleg = urow["wechselkurs_beleg"]

    rows = db.execute(
        """
        SELECT id, datum, kategorie_ar, beschreibung_ar, betrag_sar, beleg, genehmigt
        FROM kosten
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (uid,),
    ).fetchall()

    total = sum(float(r["betrag_sar"]) for r in rows) if rows else 0.0
    saldo = start - total

    ordered = [(k, KATEGORIEN[k]) for k in KATEGORIEN_ORDER]
    today = datetime.now().date().isoformat()

    db.close()
    return render_template(
        "dashboard.html",
        ordered=ordered,
        rows=rows,
        start=start,
        total=total,
        saldo=saldo,
        today=today,
        wechselkurs_beleg=wechselkurs_beleg,
    )


@app.route("/admin")
@login_required("buchhaltung")
def admin():
    db = get_db()
    kosten = db.execute(
        """
        SELECT k.*, u.username
        FROM kosten k
        JOIN users u ON u.id = k.user_id
        ORDER BY k.id DESC
        """
    ).fetchall()

    # Übersicht pro Reiseführer: Startguthaben (vom Reiseführer), Summe Ausgaben, Saldo
    users = db.execute(
        """
        SELECT
            u.id,
            u.username,
            COALESCE(u.startguthaben_sar, 0) AS startguthaben_sar,
            COALESCE(SUM(k.betrag_sar), 0)  AS total_sar
        FROM users u
        LEFT JOIN kosten k ON k.user_id = u.id
        WHERE u.role='reisefuehrer'
        GROUP BY u.id, u.username, u.startguthaben_sar
        ORDER BY u.username
        """
    ).fetchall()

    users_summary = []
    for u in users:
        start = float(u["startguthaben_sar"] or 0)
        total = float(u["total_sar"] or 0)
        users_summary.append({
            "id": u["id"],
            "username": u["username"],
            "start": start,
            "total": total,
            "saldo": start - total,
        })

    db.close()
    return render_template(
        "admin.html",
        kosten=kosten,
        users_summary=users_summary,
        alaa=session.get("username", "Buchhaltung"),
    )


@app.route("/genehmigen/<int:kid>")
@login_required("buchhaltung")
def genehmigen(kid: int):
    db = get_db()
    db.execute("UPDATE kosten SET genehmigt=1, genehmigt_von=? WHERE id=?", (session.get("username", "Alaa"), kid))
    db.commit()
    db.close()
    return redirect(url_for("admin"))



@app.route("/ablehnen/<int:kid>")
@login_required("buchhaltung")
def ablehnen(kid: int):
    db = get_db()
    db.execute("UPDATE kosten SET genehmigt=-1, genehmigt_von=? WHERE id=?", (session.get("username", "Alaa"), kid))
    db.commit()
    db.close()
    return redirect(url_for("admin"))


@app.route("/export_excel")
@login_required("buchhaltung")
def export_excel():
    from openpyxl import Workbook
    from openpyxl.utils import get_column_letter

    db = get_db()
    rows = db.execute(
        """
        SELECT k.id, u.username, u.email, u.startguthaben_sar, k.datum, k.kategorie_ar, k.beschreibung_ar,
               k.betrag_sar, k.beleg, k.genehmigt, k.genehmigt_von, k.created_at
        FROM kosten k
        JOIN users u ON u.id = k.user_id
        ORDER BY k.id DESC
        """
    ).fetchall()
    db.close()

    wb = Workbook()
    ws = wb.active
    ws.title = "Ausgaben"

    headers = ["ID", "Reiseführer", "E-Mail", "Startguthaben (SAR)", "Datum", "Kategorie (AR)",
               "Beschreibung (AR)", "Betrag (SAR)", "Beleg-Datei", "Status", "Bearbeitet von", "Erstellt am"]
    ws.append(headers)

    def status_label(v):
        try:
            v = int(v or 0)
        except Exception:
            v = 0
        if v == 1:
            return "Genehmigt"
        if v == -1:
            return "Abgelehnt"
        return "Offen"

    for r in rows:
        ws.append([
            r["id"], r["username"], r["email"], float(r["startguthaben_sar"] or 0),
            r["datum"], r["kategorie_ar"], r["beschreibung_ar"], float(r["betrag_sar"] or 0),
            r["beleg"] or "", status_label(r["genehmigt"]), r["genehmigt_von"] or "", r["created_at"] or ""
        ])

    for col in range(1, ws.max_column + 1):
        ws.column_dimensions[get_column_letter(col)].width = 18

    out_dir = app.config["UPLOAD_FOLDER"]
    os.makedirs(out_dir, exist_ok=True)
    filename = "ausgaben_export.xlsx"
    filepath = os.path.join(out_dir, filename)
    wb.save(filepath)

    return send_from_directory(out_dir, filename, as_attachment=True)


@app.route("/uploads/<filename>")
@login_required()
def uploads(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
