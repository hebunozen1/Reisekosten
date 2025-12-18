import os
import sqlite3
import secrets
import smtplib
from email.message import EmailMessage
from datetime import timedelta

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session
)
from werkzeug.security import generate_password_hash, check_password_hash


# ================== APP ==================
app = Flask(__name__)
app.secret_key = "secret-key"
app.permanent_session_lifetime = timedelta(days=7)

DB_PATH = "database.db"


# ================== DB ==================
def get_db():
    return sqlite3.connect(DB_PATH)


def ensure_schema():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            role TEXT,
            reset_token TEXT
        )
    """)
    db.commit()


@app.before_request
def init_db():
    ensure_schema()


# ================== SMTP ==================
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 465))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")


def send_reset_email(to_email, reset_link):
    msg = EmailMessage()
    msg["Subject"] = "Passwort zurücksetzen"
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content(
        f"""Hallo,

bitte klicke auf folgenden Link, um dein Passwort zurückzusetzen:

{reset_link}

Falls du das nicht angefordert hast, ignoriere diese E-Mail.
"""
    )

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)


# ================== AUTH ==================
@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Bitte E-Mail und Passwort eingeben.", "error")
            return render_template("login.html")

        db = get_db()
        user = db.execute(
            "SELECT id, password, role FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not user or not check_password_hash(user[1], password):
            flash("Login fehlgeschlagen.", "error")
            return render_template("login.html")

        session["user_id"] = user[0]
        session["role"] = user[2]
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        role = request.form.get("role", "reisefuehrer")

        if not username or not email or not password:
            flash("Bitte alle Felder ausfüllen.", "error")
            return render_template("register.html")

        if password != password2:
            flash("Passwörter stimmen nicht überein.", "error")
            return render_template("register.html")

        pw_hash = generate_password_hash(password)
        db = get_db()

        try:
            db.execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                (username, email, pw_hash,_
