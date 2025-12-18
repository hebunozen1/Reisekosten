
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3, secrets, smtplib
from email.message import EmailMessage
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret"
app.permanent_session_lifetime = timedelta(days=7)

DB = "database.db"

# ====== DB ======
def get_db():
    return sqlite3.connect(DB)

def ensure_schema():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password TEXT,
        role TEXT,
        reset_token TEXT
    )""")
    db.commit()

@app.before_request
def _init():
    ensure_schema()

# ====== MAIL ======
SMTP_HOST = "smtp.example.com"
SMTP_PORT = 465
SMTP_USER = "noreply@example.com"
SMTP_PASS = "APP_PASSWORT"

def send_reset_email(to_email, reset_link):
    msg = EmailMessage()
    msg["Subject"] = "Passwort zurücksetzen"
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content(f"""Hallo,

bitte klicke auf folgenden Link, um dein Passwort zurückzusetzen:

{reset_link}

Falls du das nicht angefordert hast, ignoriere diese E-Mail.
""")

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)

# ====== AUTH ======
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").lower().strip()
        password = request.form.get("password","")

        if not email or not password:
            flash("Bitte E-Mail und Passwort eingeben.")
            return render_template("login.html")

        db = get_db()
        user = db.execute("SELECT id,password FROM users WHERE email=?",(email,)).fetchone()
        if not user or not check_password_hash(user[1], password):
            flash("Login fehlgeschlagen.")
            return render_template("login.html")

        session["user_id"] = user[0]
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/forgot", methods=["GET","POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email","").lower().strip()
        if not email:
            flash("Bitte E-Mail eingeben.")
            return render_template("forgot.html")

        token = secrets.token_urlsafe(32)
        db = get_db()
        db.execute("UPDATE users SET reset_token=? WHERE email=?", (token,email))
        db.commit()

       reset_link = url_for("reset", token=token, _external=True)

try:
    send_reset_email(email, reset_link)
except Exception as e:
    print("MAIL ERROR:", e)
    flash(
        "Die E-Mail konnte aktuell nicht gesendet werden. "
        "Bitte versuche es später erneut.",
        "error"
    )
    return render_template("forgot.html")

flash("Wir haben dir eine E-Mail zum Zurücksetzen gesendet.", "success")
return redirect(url_for("login"))


    return render_template("forgot.html")

@app.route("/reset/<token>", methods=["GET","POST"])
def reset(token):
    if request.method == "POST":
        password = request.form.get("password","")
        password2 = request.form.get("password2","")
        if not password or password != password2:
            flash("Passwörter stimmen nicht.")
            return render_template("reset.html")

        db = get_db()
        db.execute(
            "UPDATE users SET password=?, reset_token=NULL WHERE reset_token=?",
            (generate_password_hash(password), token)
        )
        db.commit()

        flash("Passwort erfolgreich geändert.")
        return redirect(url_for("login"))

    return render_template("reset.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

