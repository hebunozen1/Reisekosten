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
        conn = psycopg2.connect(DATABASE_URL)
        conn.cursor_factory = psycopg2.extras.RealDictCursor
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

    conn.commit()
    conn.close()

ensure_schema()

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
    action = None
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
            if action in ("approve", "deny"):
                kid = request.form.get("kid")
                if not kid:
                    return redirect(url_for("dashboard"))

                conn = get_db()
                cur = conn.cursor()
                genehmigt_val = 1 if action == "approve" else -1

                # Status aktualisieren (Ablehnung wird NICHT gutgeschrieben – Kontostand ergibt sich aus Startguthaben - Summe Ausgaben)
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

                conn.commit()
                conn.close()
                flash("Status aktualisiert", "ok")
                return redirect(url_for("dashboard"))

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


