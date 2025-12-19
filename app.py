import os
import sqlite3
import uuid
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

# =====================
# Flask App
# =====================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# =====================
# Datenbank
# =====================
DB_PATH = "reisekosten.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # <<< WICHTIG
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
            flash("Bitte alle Felder ausfüllen.")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()

        # Prüfen, ob E-Mail schon existiert
        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            conn.close()
            flash("E-Mail ist bereits registriert.")
            return redirect(url_for("register"))

        # Benutzer anlegen
        cur.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
            (username, email, pw_hash, role)
        )
        conn.commit()
        conn.close()

        flash("Registrierung erfolgreich. Bitte einloggen.")
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
            flash("Bitte E-Mail und Passwort eingeben.")
            return redirect(url_for("login"))

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Login fehlgeschlagen.")
        return redirect(url_for("login"))

    return render_template("login.html")

# =====================
# Dashboard
# =====================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", role=session.get("role"))

# =====================
# Logout
# =====================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =====================
# App starten (lokal)
# =====================
if __name__ == "__main__":
    app.run(debug=True)
