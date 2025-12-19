import os
import sqlite3
import uuid
import hashlib
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg2
import psycopg2.extras

# =====================
# Flask App
# =====================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# =====================
# Database
# =====================
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    if DATABASE_URL:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        return conn
    else:
        return sqlite3.connect("reisekosten.db")

def ensure_schema():
    conn = get_db()
    cur = conn.cursor()

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

    conn.commit()
    conn.close()

@app.before_request
def before_request():
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
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s" if DATABASE_URL else
                    "SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Login fehlgeschlagen")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form.get("role", "reisefuehrer")

        pw_hash = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (%s,%s,%s,%s)"
            if DATABASE_URL else
            "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
            (username, email, pw_hash, role)
        )
        conn.commit()
        conn.close()

        flash("Registrierung erfolgreich")
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

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


