import os
import sqlite3

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg2
import psycopg2.extras

# =====================
# Flask App
# =====================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

DATABASE_URL = os.environ.get("DATABASE_URL")

# =====================
# Datenbank
# =====================
def get_db():
    if DATABASE_URL:
        conn = psycopg2.connect(DATABASE_URL)
        conn.cursor_factory = psycopg2.extras.RealDictCursor
        return conn
    else:
        conn = sqlite3.connect("reisekosten.db")
        conn.row_factory = sqlite3.Row
        return conn

# =====================
# Startseite
# =====================
@app.route("/")
def index():
    return redirect(url_for("login"))

# =====================
# Registrierung
# =====================
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

        if cur.fetchone():
            conn.close()
            flash("E-Mail ist bereits registriert")
            return redirect(url_for("register"))

        cur.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (%s,%s,%s,%s)"
            if DATABASE_URL else
            "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
            (username, email, pw_hash, role)
        )

        conn.commit()
        conn.close()

        flash("Registrierung erfolgreich – bitte einloggen")
        return redirect(url_for("login"))

    return render_template("register.html")

# =====================
# Login
# =====================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Bitte E-Mail und Passwort eingeben")
            return redirect(url_for("login"))

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
            pw_hash = user["password_hash"] if isinstance(user, dict) else user[3]

            if check_password_hash(pw_hash, password):
                session["user_id"] = user["id"] if isinstance(user, dict) else user[0]
                session["role"] = user["role"] if isinstance(user, dict) else user[4]
                return redirect(url_for("dashboard"))

        flash("Login fehlgeschlagen")
        return redirect(url_for("login"))

    return render_template("login.html")

# =====================
# Dashboard
# =====================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        role=session.get("role"),
        start=0.0,
        total=0.0,
        approved=0.0,
        pending=0.0,
        rejected=0.0
    )

# =====================
# Logout
# =====================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =====================
# Start (lokal)
# =====================
if __name__ == "__main__":
    app.run(debug=True)
