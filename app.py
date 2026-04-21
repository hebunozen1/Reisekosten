import os
import sqlite3
import uuid
import hashlib
import smtplib
import io
import csv
import zipfile
import tempfile
import re
import time
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import requests
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
APPROVER_EMAIL = (os.environ.get("APPROVAL_APPROVER_EMAIL") or "hebun.oezen@gmx.de").strip().lower()

ARABIC_RE = re.compile(r"[\u0600-\u06FF]")


def contains_arabic(text: str | None) -> bool:
    """Return True if a text contains Arabic characters."""
    return bool(ARABIC_RE.search(text or ""))


def translation_is_missing_or_not_german(source_text: str | None, translated_text: str | None) -> bool:
    """Detect old entries where beschreibung_de is empty or still contains the Arabic original."""
    source = (source_text or "").strip()
    translated = (translated_text or "").strip()
    if not source or not contains_arabic(source):
        return False
    return (not translated) or translated == source or contains_arabic(translated)


def translate_arabic_to_german(text: str | None) -> str:
    """Translate Arabic expense descriptions to German. Fallback keeps the original text."""
    source = (text or "").strip()
    if not source:
        return ""
    if not contains_arabic(source):
        return source

    if not _env_bool("AUTO_TRANSLATE_DESCRIPTIONS", True):
        return source

    try:
        timeout_seconds = float(os.environ.get("TRANSLATE_TIMEOUT_SECONDS", "2.5"))
        response = requests.get(
            "https://translate.googleapis.com/translate_a/single",
            params={
                "client": "gtx",
                "sl": "ar",
                "tl": "de",
                "dt": "t",
                "q": source,
            },
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        translated = "".join(part[0] for part in data[0] if part and part[0]).strip()
        return translated or source
    except Exception as exc:
        app.logger.warning("Beschreibung konnte nicht automatisch übersetzt werden: %s", exc)
        return source


def translate_and_store_missing_descriptions(cur, kosten_rows, max_items=8, time_budget_seconds=10):
    """Translate a small batch of missing German descriptions and persist them.

    Important: this function is intentionally limited. External translation calls can be slow
    or unavailable. A bulk translation during normal dashboard loading can block the Render
    worker and cause a timeout.
    """
    changed = 0
    started = time.monotonic()
    for row in kosten_rows:
        if max_items is not None and changed >= max_items:
            break
        if time_budget_seconds is not None and (time.monotonic() - started) >= time_budget_seconds:
            break

        source = row.get("beschreibung_ar")
        current = row.get("beschreibung_de")
        if not translation_is_missing_or_not_german(source, current):
            continue

        translated = translate_arabic_to_german(source)
        if not translated or translated.strip() == (source or "").strip():
            continue

        row["beschreibung_de"] = translated
        cur.execute(
            "UPDATE kosten SET beschreibung_de=%s WHERE id=%s" if DATABASE_URL else
            "UPDATE kosten SET beschreibung_de=? WHERE id=?",
            (translated, row.get("id")),
        )
        changed += 1
    return changed

def normalize_email(email: str | None) -> str:
    """Normalize emails for consistent lookup (trim + lower)."""
    return (email or "").strip().lower()


def row_value(row, key, default=None):
    """Return a column value for both dict-like rows and sqlite3.Row."""
    if row is None:
        return default
    if hasattr(row, "keys") and key in row.keys():
        return row[key]
    try:
        return row[key]
    except Exception:
        return default


def _as_utc_naive(value):
    """Convert datetimes to naive UTC so SQLite and PostgreSQL values are comparable."""
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def parse_reset_expiry(raw_value):
    """Parse reset expiry values from SQLite text or native datetime objects."""
    if raw_value is None:
        return None
    if isinstance(raw_value, datetime):
        return _as_utc_naive(raw_value)
    if isinstance(raw_value, str):
        value = raw_value.strip()
        if not value:
            return None
        try:
            return _as_utc_naive(datetime.fromisoformat(value))
        except ValueError:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    return None

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


def ensure_user_reset_columns(cur):
    if DATABASE_URL:
        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'users'
              AND column_name IN ('reset_token', 'reset_token_expires')
        """)
        existing = {row['column_name'] if hasattr(row, 'keys') else row[0] for row in cur.fetchall()}
        if 'reset_token' not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
        if 'reset_token_expires' not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token_expires TIMESTAMP")
    else:
        cur.execute("PRAGMA table_info(users)")
        existing = {row['name'] if hasattr(row, 'keys') else row[1] for row in cur.fetchall()}
        if 'reset_token' not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
        if 'reset_token_expires' not in existing:
            cur.execute("ALTER TABLE users ADD COLUMN reset_token_expires TEXT")

def ensure_user_approval_columns(cur):
    ensure_column(
        cur,
        "users",
        "approval_status",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'approved'",
        "ALTER TABLE users ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'approved'",
    )
    ensure_column(
        cur,
        "users",
        "approved_at",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN approved_at TEXT",
    )
    ensure_column(
        cur,
        "users",
        "approved_by_email",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_by_email TEXT",
        "ALTER TABLE users ADD COLUMN approved_by_email TEXT",
    )


def ensure_column(cur, table_name, column_name, postgres_sql, sqlite_sql):
    if DATABASE_URL:
        cur.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = %s AND column_name = %s
            """,
            (table_name, column_name),
        )
        exists = cur.fetchone()
        if not exists:
            cur.execute(postgres_sql)
    else:
        cur.execute(f"PRAGMA table_info({table_name})")
        columns = {row['name'] if hasattr(row, 'keys') else row[1] for row in cur.fetchall()}
        if column_name not in columns:
            cur.execute(sqlite_sql)


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
            reset_token_expires TIMESTAMP
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
            reset_token_expires TEXT
        )
        """)

    ensure_user_reset_columns(cur)
    ensure_user_approval_columns(cur)

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


    # ---- kosten migration: Reisebezug ----
    ensure_column(
        cur,
        "kosten",
        "reise_name",
        "ALTER TABLE kosten ADD COLUMN IF NOT EXISTS reise_name TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE kosten ADD COLUMN reise_name TEXT NOT NULL DEFAULT ''",
    )

    # ---- vorschuesse ----
    if DATABASE_URL:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS vorschuesse (
            id BIGSERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            datum DATE,
            reise_name TEXT NOT NULL DEFAULT '',
            beschreibung TEXT NOT NULL DEFAULT '',
            betrag_sar NUMERIC NOT NULL DEFAULT 0,
            beleg TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
    else:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS vorschuesse (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            datum TEXT,
            reise_name TEXT NOT NULL DEFAULT '',
            beschreibung TEXT NOT NULL DEFAULT '',
            betrag_sar REAL NOT NULL DEFAULT 0,
            beleg TEXT,
            created_at TEXT
        )
        """)

    # ---- migration: hide entries from Buchhaltung without deleting for Reiseführer ----
    ensure_column(
        cur,
        "kosten",
        "buchhaltung_deleted",
        "ALTER TABLE kosten ADD COLUMN IF NOT EXISTS buchhaltung_deleted INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE kosten ADD COLUMN buchhaltung_deleted INTEGER NOT NULL DEFAULT 0",
    )

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
        print("DB schema init failed:", repr(e), flush=True)
        raise


# =====================
# SMTP – STRATO
# =====================
def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def build_reset_link(token: str) -> str:
    public_base_url = (os.environ.get("PUBLIC_BASE_URL") or "").strip().rstrip("/")
    if public_base_url:
        return f"{public_base_url}{url_for('reset', token=token)}"
    return url_for("reset", token=token, _external=True)


# =====================
# SMTP – allgemein
# =====================
def send_smtp_message(to_email, subject, body):
    host = (os.environ.get("SMTP_HOST") or "").strip()
    port = int(os.environ.get("SMTP_PORT", 587))
    user = (os.environ.get("SMTP_USER") or "").strip()
    password = os.environ.get("SMTP_PASSWORD") or ""
    from_email = (os.environ.get("SMTP_FROM") or user).strip()

    missing = []
    if not host:
        missing.append("SMTP_HOST")
    if not user:
        missing.append("SMTP_USER")
    if not password:
        missing.append("SMTP_PASSWORD")
    if not from_email:
        missing.append("SMTP_FROM")

    if missing:
        raise RuntimeError(
            "SMTP-Konfiguration unvollständig. Fehlend: " + ", ".join(missing)
        )

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    use_ssl = _env_bool("SMTP_USE_SSL", port == 465)
    use_tls = _env_bool("SMTP_USE_TLS", not use_ssl)

    print(f"SMTP: connecting to {host}:{port} ssl={use_ssl} tls={use_tls}")
    server = None
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
            server.ehlo()
        else:
            server = smtplib.SMTP(host, port, timeout=15)
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()

        server.login(user, password)
        server.sendmail(from_email, [to_email], msg.as_string())
        print("SMTP: mail sent")
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


def send_reset_email(to_email, reset_link):
    body = f"""
Hallo,

du kannst dein Passwort über folgenden Link zurücksetzen:

{reset_link}

Der Link ist 30 Minuten gültig.

Falls du das nicht warst, ignoriere diese E-Mail.
"""
    send_smtp_message(to_email, "Passwort zurücksetzen", body)


def send_registration_request_email(pending_user_email, pending_username, requested_role):
    role_label = "Buchhaltung" if requested_role == "buchhaltung" else "Reiseführer"
    approval_link = (os.environ.get("PUBLIC_BASE_URL") or "").strip().rstrip("/") or request.host_url.rstrip("/")
    body = f"""
Hallo,

es gibt eine neue Registrierungsanfrage für die Reisekosten-App.

Benutzername: {pending_username}
E-Mail: {pending_user_email}
Gewünschte Rolle: {role_label}

Bitte melde dich als Buchhalter an und prüfe die Anfrage im Bereich "Registrierungsanfragen":
{approval_link}{url_for('dashboard')}
"""
    send_smtp_message(APPROVER_EMAIL, "Neue Registrierungsanfrage", body)


def send_registration_approved_email(to_email, username, role):
    role_label = "Buchhaltung" if role == "buchhaltung" else "Reiseführer"
    login_link = (os.environ.get("PUBLIC_BASE_URL") or "").strip().rstrip("/") or request.host_url.rstrip("/")
    body = f"""
Hallo {username},

deine Registrierungsanfrage für die Reisekosten-App wurde freigegeben.

Freigegebene Rolle: {role_label}
Login: {login_link}{url_for('login')}

Du kannst dich ab sofort anmelden.
"""
    send_smtp_message(to_email, "Registrierung freigegeben", body)



# =====================
# Routes
# =====================
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    selected_role = request.args.get("role", "reisefuehrer")

    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password")

        if not email or not password:
            flash("Bitte E-Mail und Passwort eingeben")
            return redirect(url_for("login", role=selected_role))

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, email, password_hash, role, COALESCE(approval_status, 'approved') AS approval_status FROM users WHERE LOWER(email)=LOWER(%s)"
            if DATABASE_URL else
            "SELECT id, username, email, password_hash, role, COALESCE(approval_status, 'approved') AS approval_status FROM users WHERE LOWER(email)=LOWER(?)",
            (email,)
        )
        user = cur.fetchone()
        conn.close()

        if not user:
            flash("Login fehlgeschlagen")
            return redirect(url_for("login", role=selected_role))

        approval_status = row_value(user, "approval_status", user[5] if not hasattr(user, "keys") and len(user) > 5 else "approved")
        if approval_status == "pending":
            flash("Dein Konto wartet noch auf Freigabe.", "err")
            return redirect(url_for("login", role=selected_role))
        if approval_status == "rejected":
            flash("Deine Registrierungsanfrage wurde abgelehnt. Bitte kontaktiere die Buchhaltung.", "err")
            return redirect(url_for("login", role=selected_role))

        pw_hash = user["password_hash"] if hasattr(user, "keys") else user[3]
        if pw_hash and check_password_hash(pw_hash, password):
            session["user_id"] = user["id"] if hasattr(user, "keys") else user[0]
            session["role"] = user["role"] if hasattr(user, "keys") else user[4]
            session["username"] = user["username"] if hasattr(user, "keys") else user[1]
            session["email"] = normalize_email(row_value(user, "email", user[2] if not hasattr(user, "keys") else ""))
            return redirect(url_for("dashboard"))

        flash("Login fehlgeschlagen")
        return redirect(url_for("login", role=selected_role))

    return render_template("login.html", role=selected_role)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        role = (request.form.get("role") or "reisefuehrer").strip()
        if role not in ("reisefuehrer", "buchhaltung"):
            role = "reisefuehrer"

        if not username or not email or not password:
            flash("Bitte alle Felder ausfüllen", "err")
            return redirect(url_for("register"))
        if password != password2:
            flash("Die Passwörter stimmen nicht überein.", "err")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT id, username, email, password_hash, role, COALESCE(approval_status, 'approved') AS approval_status FROM users WHERE LOWER(email) = LOWER(%s)"
                if DATABASE_URL else
                "SELECT id, username, email, password_hash, role, COALESCE(approval_status, 'approved') AS approval_status FROM users WHERE LOWER(email) = LOWER(?)",
                (email,)
            )
            existing_email = cur.fetchone()

            cur.execute(
                "SELECT id, email FROM users WHERE LOWER(username) = LOWER(%s)"
                if DATABASE_URL else
                "SELECT id, email FROM users WHERE LOWER(username) = LOWER(?)",
                (username,)
            )
            existing_username = cur.fetchone()

            if existing_email:
                status = row_value(existing_email, "approval_status", "approved")
                if status == "pending":
                    flash("Für diese E-Mail gibt es bereits eine offene Registrierungsanfrage.", "err")
                    return redirect(url_for("login"))
                if status == "rejected":
                    flash("Diese E-Mail wurde bereits abgelehnt. Bitte kontaktiere die Buchhaltung.", "err")
                    return redirect(url_for("login"))
                flash("E-Mail ist bereits registriert – bitte Passwort zurücksetzen, falls du es vergessen hast.", "err")
                return redirect(url_for("forgot"))

            if existing_username:
                existing_username_email = normalize_email(row_value(existing_username, "email", ""))
                if existing_username_email != email:
                    flash("Der Benutzername ist bereits vergeben.", "err")
                    return redirect(url_for("register"))

            if DATABASE_URL:
                cur.execute(
                    "INSERT INTO users (username, email, password_hash, role, approval_status, approved_at, approved_by_email) VALUES (%s,%s,%s,%s,%s,NULL,NULL)",
                    (username, email, pw_hash, role, "pending")
                )
            else:
                cur.execute(
                    "INSERT INTO users (username, email, password_hash, role, approval_status, approved_at, approved_by_email) VALUES (?,?,?,?,?,NULL,NULL)",
                    (username, email, pw_hash, role, "pending")
                )
            conn.commit()
        finally:
            conn.close()

        flash("Registrierungsanfrage gespeichert. Du kannst dich nach Freigabe anmelden.", "ok")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        if not email:
            flash("Bitte eine E-Mail-Adresse eingeben.", "error")
            return redirect(url_for("forgot"))

        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM users WHERE LOWER(email) = LOWER(%s)" if DATABASE_URL else
                "SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email,)
            )
            user = cur.fetchone()

            if user:
                token = uuid.uuid4().hex
                expires = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=30)
                expires_db_value = expires if DATABASE_URL else expires.strftime("%Y-%m-%d %H:%M:%S")

                cur.execute(
                    "UPDATE users SET reset_token=%s, reset_token_expires=%s WHERE id=%s"
                    if DATABASE_URL else
                    "UPDATE users SET reset_token=?, reset_token_expires=? WHERE id=?",
                    (token, expires_db_value, row_value(user, "id"))
                )
                conn.commit()

                reset_link = build_reset_link(token)
                try:
                    send_reset_email(row_value(user, "email"), reset_link)
                except Exception as exc:
                    app.logger.exception("Password reset e-mail could not be sent for %s", email)
                    flash(f"Die Reset-E-Mail konnte nicht versendet werden: {exc}", "error")
                    return redirect(url_for("forgot"))
        finally:
            conn.close()

        flash("Wenn die E-Mail existiert, wurde eine Nachricht versendet.")
        return redirect(url_for("login"))

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM users WHERE reset_token=%s"
            if DATABASE_URL else
            "SELECT * FROM users WHERE reset_token=?",
            (token,)
        )
        user = cur.fetchone()

        expires_at = parse_reset_expiry(row_value(user, "reset_token_expires"))
        if not user or expires_at is None or expires_at < datetime.now(timezone.utc).replace(tzinfo=None):
            flash("Der Reset-Link ist abgelaufen.", "error")
            return redirect(url_for("login"))

        if request.method == "POST":
            password = (request.form.get("password") or "").strip()
            password2 = (request.form.get("password2") or "").strip()
            if not password:
                flash("Bitte ein neues Passwort eingeben.", "error")
                return redirect(url_for("reset", token=token))
            if password != password2:
                flash("Die Passwörter stimmen nicht überein.", "error")
                return redirect(url_for("reset", token=token))

            pw_hash = generate_password_hash(password)
            cur.execute(
                "UPDATE users SET password_hash=%s, reset_token=NULL, reset_token_expires=NULL WHERE id=%s"
                if DATABASE_URL else
                "UPDATE users SET password_hash=?, reset_token=NULL, reset_token_expires=NULL WHERE id=?",
                (pw_hash, row_value(user, "id"))
            )
            conn.commit()

            flash("Passwort erfolgreich geändert")
            return redirect(url_for("login"))

        return render_template("reset.html")
    finally:
        conn.close()


@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
        as_attachment=False
    )


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


def normalize_trip_name(value: str | None) -> str:
    return (value or "").strip()


def month_from_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m")
    text = str(value).strip()
    return text[:7] if len(text) >= 7 else ""


def entry_matches_filters(entry, month_filter="", trip_filter=""):
    if month_filter and month_from_value(entry.get("datum")) != month_filter:
        return False
    if trip_filter and normalize_trip_name(entry.get("reise_name")) != trip_filter:
        return False
    return True


def _status_text(status: int) -> str:
    if status == 1:
        return "Genehmigt"
    if status == -1:
        return "Abgelehnt"
    return "Offen"


def fetch_startbetrag(cur, user_id):
    cur.execute(
        "SELECT betrag_sar FROM startguthaben WHERE user_id=%s" if DATABASE_URL else
        "SELECT betrag_sar FROM startguthaben WHERE user_id=?",
        (user_id,),
    )
    row = cur.fetchone()
    return float(row_value(row, "betrag_sar", 0) if row else 0)


def fetch_wechselkurs_beleg(cur, user_id):
    cur.execute(
        "SELECT wechselkurs_beleg FROM startguthaben WHERE user_id=%s" if DATABASE_URL else
        "SELECT wechselkurs_beleg FROM startguthaben WHERE user_id=?",
        (user_id,),
    )
    row = cur.fetchone()
    return row_value(row, "wechselkurs_beleg") if row else None


def is_missing_db_object_error(exc, *names):
    message = str(exc).lower()
    return any(name.lower() in message for name in names)


def fetch_users(cur):
    cur.execute(
        "SELECT id, username FROM users WHERE role=%s AND COALESCE(approval_status, 'approved')=%s ORDER BY username" if DATABASE_URL else
        "SELECT id, username FROM users WHERE role=? AND COALESCE(approval_status, 'approved')=? ORDER BY username",
        ("reisefuehrer", "approved"),
    )
    rows = cur.fetchall() or []
    result = []
    for row in rows:
        result.append({
            "id": row_value(row, "id", row[0] if not hasattr(row, "keys") else None),
            "username": row_value(row, "username", row[1] if not hasattr(row, "keys") else ""),
        })
    return result

def is_request_approver():
    return session.get("role") == "buchhaltung" and normalize_email(session.get("email")) == APPROVER_EMAIL


def fetch_pending_registrations(cur):
    cur.execute(
        "SELECT id, username, email, role, COALESCE(approval_status, 'approved') AS approval_status FROM users WHERE COALESCE(approval_status, 'approved')=%s ORDER BY id DESC"
        if DATABASE_URL else
        "SELECT id, username, email, role, COALESCE(approval_status, 'approved') AS approval_status FROM users WHERE COALESCE(approval_status, 'approved')=? ORDER BY id DESC",
        ("pending",),
    )
    rows = cur.fetchall() or []
    result = []
    for row in rows:
        result.append({
            "id": row_value(row, "id"),
            "username": row_value(row, "username", ""),
            "email": normalize_email(row_value(row, "email", "")),
            "role": row_value(row, "role", "reisefuehrer"),
            "approval_status": row_value(row, "approval_status", "pending"),
        })
    return result


def fetch_kosten(cur, user_id=None, include_username=False):
    rows_raw = None
    try:
        if include_username:
            query = """
                SELECT k.id, k.user_id, u.username, k.datum, k.kategorie_ar, k.kategorie_de,
                       k.beschreibung_ar, k.beschreibung_de, k.betrag_sar, k.beleg,
                       k.genehmigt, k.genehmigt_von, k.reise_name
                FROM kosten k
                JOIN users u ON u.id = k.user_id
                WHERE COALESCE(k.buchhaltung_deleted,0)=0
            """
            params = []
            if user_id is not None:
                query += " AND k.user_id=%s" if DATABASE_URL else " AND k.user_id=?"
                params.append(user_id)
            query += " ORDER BY k.datum DESC, k.id DESC"
            cur.execute(query, tuple(params))
        else:
            cur.execute(
                "SELECT id, user_id, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de, betrag_sar, beleg, genehmigt, genehmigt_von, reise_name FROM kosten WHERE user_id=%s ORDER BY datum DESC, id DESC"
                if DATABASE_URL else
                "SELECT id, user_id, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de, betrag_sar, beleg, genehmigt, genehmigt_von, reise_name FROM kosten WHERE user_id=? ORDER BY datum DESC, id DESC",
                (user_id,),
            )
        rows_raw = cur.fetchall() or []
    except Exception as exc:
        if not is_missing_db_object_error(exc, 'reise_name', 'buchhaltung_deleted'):
            raise
        # Fallback for old databases where the migration has not run yet.
        if include_username:
            query = """
                SELECT k.id, k.user_id, u.username, k.datum, k.kategorie_ar, k.kategorie_de,
                       k.beschreibung_ar, k.beschreibung_de, k.betrag_sar, k.beleg,
                       k.genehmigt, k.genehmigt_von
                FROM kosten k
                JOIN users u ON u.id = k.user_id
                ORDER BY k.datum DESC, k.id DESC
            """
            params = []
            if user_id is not None:
                query = query.replace('ORDER BY', ("WHERE k.user_id=%s ORDER BY" if DATABASE_URL else "WHERE k.user_id=? ORDER BY"), 1)
                params.append(user_id)
            cur.execute(query, tuple(params))
        else:
            cur.execute(
                "SELECT id, user_id, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de, betrag_sar, beleg, genehmigt, genehmigt_von FROM kosten WHERE user_id=%s ORDER BY datum DESC, id DESC"
                if DATABASE_URL else
                "SELECT id, user_id, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de, betrag_sar, beleg, genehmigt, genehmigt_von FROM kosten WHERE user_id=? ORDER BY datum DESC, id DESC",
                (user_id,),
            )
        rows_raw = cur.fetchall() or []

    rows = []
    for row in rows_raw:
        rows.append({
            "id": row_value(row, "id", row[0] if not hasattr(row, "keys") else None),
            "user_id": row_value(row, "user_id", row[1] if not hasattr(row, "keys") else None),
            "username": row_value(row, "username", ""),
            "datum": str(row_value(row, "datum", row[2] if not hasattr(row, "keys") else ""))[:10],
            "kategorie_ar": row_value(row, "kategorie_ar", ""),
            "kategorie_de": row_value(row, "kategorie_de", ""),
            "beschreibung_ar": row_value(row, "beschreibung_ar", ""),
            "beschreibung_de": row_value(row, "beschreibung_de", ""),
            "betrag_sar": float(row_value(row, "betrag_sar", 0) or 0),
            "beleg": row_value(row, "beleg"),
            "genehmigt": int(row_value(row, "genehmigt", 0) or 0),
            "genehmigt_von": row_value(row, "genehmigt_von", ""),
            "reise_name": normalize_trip_name(row_value(row, "reise_name", "")),
        })
    return rows


def fetch_vorschuesse(cur, user_id=None, include_username=False):
    if include_username:
        query = """
            SELECT v.id, v.user_id, u.username, v.datum, v.reise_name, v.beschreibung,
                   v.betrag_sar, v.beleg
            FROM vorschuesse v
            JOIN users u ON u.id = v.user_id
        """
        params = []
        if user_id is not None:
            query += " WHERE v.user_id=%s" if DATABASE_URL else " WHERE v.user_id=?"
            params.append(user_id)
        query += " ORDER BY v.datum DESC, v.id DESC"
        cur.execute(query, tuple(params))
    else:
        cur.execute(
            "SELECT id, user_id, datum, reise_name, beschreibung, betrag_sar, beleg FROM vorschuesse WHERE user_id=%s ORDER BY datum DESC, id DESC"
            if DATABASE_URL else
            "SELECT id, user_id, datum, reise_name, beschreibung, betrag_sar, beleg FROM vorschuesse WHERE user_id=? ORDER BY datum DESC, id DESC",
            (user_id,),
        )
    rows = []
    for row in (cur.fetchall() or []):
        rows.append({
            "id": row_value(row, "id", row[0] if not hasattr(row, "keys") else None),
            "user_id": row_value(row, "user_id", row[1] if not hasattr(row, "keys") else None),
            "username": row_value(row, "username", ""),
            "datum": str(row_value(row, "datum", row[2] if not hasattr(row, "keys") else ""))[:10],
            "reise_name": normalize_trip_name(row_value(row, "reise_name", row[3] if not hasattr(row, "keys") else "")),
            "beschreibung": row_value(row, "beschreibung", row[4] if not hasattr(row, "keys") else ""),
            "betrag_sar": float(row_value(row, "betrag_sar", row[5] if not hasattr(row, "keys") else 0) or 0),
            "beleg": row_value(row, "beleg", row[6] if not hasattr(row, "keys") else None),
        })
    return rows


def unique_trip_names(*collections):
    values = set()
    for collection in collections:
        for row in collection:
            name = normalize_trip_name(row.get("reise_name"))
            if name:
                values.add(name)
    return sorted(values, key=lambda x: x.lower())


def compute_scope_summary(start_amount, kosten_rows, vorschuss_rows, month_filter="", trip_filter=""):
    filtered_kosten = [r for r in kosten_rows if r.get("genehmigt") != -1 and entry_matches_filters(r, month_filter, trip_filter)]
    filtered_vorschuesse = [r for r in vorschuss_rows if entry_matches_filters(r, month_filter, trip_filter)]

    if month_filter:
        previous_kosten = [
            r for r in kosten_rows
            if r.get("genehmigt") != -1
            and (not trip_filter or normalize_trip_name(r.get("reise_name")) == trip_filter)
            and month_from_value(r.get("datum")) < month_filter
        ]
        previous_vorschuesse = [
            r for r in vorschuss_rows
            if (not trip_filter or normalize_trip_name(r.get("reise_name")) == trip_filter)
            and month_from_value(r.get("datum")) < month_filter
        ]
        opening = (0.0 if trip_filter else start_amount) + sum(r["betrag_sar"] for r in previous_vorschuesse) - sum(r["betrag_sar"] for r in previous_kosten)
    else:
        opening = 0.0 if trip_filter else start_amount

    vorschuss_total = sum(r["betrag_sar"] for r in filtered_vorschuesse)
    kosten_total = sum(r["betrag_sar"] for r in filtered_kosten)
    closing = opening + vorschuss_total - kosten_total

    return {
        "opening": opening,
        "vorschuss_total": vorschuss_total,
        "kosten_total": kosten_total,
        "closing": closing,
        "filtered_kosten": filtered_kosten,
        "filtered_vorschuesse": filtered_vorschuesse,
    }


def aggregate_summaries(user_ids, start_map, kosten_rows, vorschuss_rows, month_filter="", trip_filter=""):
    summary = {"opening": 0.0, "vorschuss_total": 0.0, "kosten_total": 0.0, "closing": 0.0}
    for user_id in user_ids:
        user_kosten = [row for row in kosten_rows if row["user_id"] == user_id]
        user_vorschuesse = [row for row in vorschuss_rows if row["user_id"] == user_id]
        user_summary = compute_scope_summary(start_map.get(user_id, 0.0), user_kosten, user_vorschuesse, month_filter, trip_filter)
        for key in summary:
            summary[key] += user_summary[key]
    return summary


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    role = session.get("role", "reisefuehrer")
    uid = session["user_id"]

    if request.method == "POST":
        action = request.form.get("action")

        if role == "buchhaltung":
            kid = request.form.get("kid")
            pending_user_id = request.form.get("pending_user_id")
            conn = get_db()
            cur = conn.cursor()
            try:
                if action == "translate_descriptions":
                    month_filter_post = (request.args.get("monat") or "").strip()
                    trip_filter_post = normalize_trip_name(request.args.get("reise"))
                    selected_user_id_raw_post = (request.args.get("user_id") or "").strip()
                    selected_user_id_post = int(selected_user_id_raw_post) if selected_user_id_raw_post.isdigit() else None
                    rows_to_translate = fetch_kosten(cur, include_username=True)
                    if selected_user_id_post:
                        rows_to_translate = [row for row in rows_to_translate if row["user_id"] == selected_user_id_post]
                    rows_to_translate = [row for row in rows_to_translate if entry_matches_filters(row, month_filter_post, trip_filter_post)]
                    translated_count = translate_and_store_missing_descriptions(
                        cur, rows_to_translate, max_items=8, time_budget_seconds=12
                    )
                    conn.commit()
                    if translated_count:
                        flash(f"{translated_count} Beschreibung(en) wurden übersetzt. Wenn noch arabische Texte vorhanden sind, den Button erneut klicken.", "ok")
                    else:
                        flash("Keine neuen Übersetzungen gefunden oder der Übersetzungsdienst hat nicht schnell genug geantwortet.", "err")
                elif action in ("approve", "deny") and kid:
                    genehmigt_val = 1 if action == "approve" else -1
                    cur.execute(
                        "UPDATE kosten SET genehmigt=%s, genehmigt_von=%s WHERE id=%s" if DATABASE_URL else
                        "UPDATE kosten SET genehmigt=?, genehmigt_von=? WHERE id=?",
                        (genehmigt_val, session.get("username", ""), kid),
                    )
                    conn.commit()
                    flash("Status aktualisiert", "ok")
                elif action == "delete_admin" and kid:
                    cur.execute(
                        "DELETE FROM kosten WHERE id=%s" if DATABASE_URL else
                        "DELETE FROM kosten WHERE id=?",
                        (kid,),
                    )
                    conn.commit()
                    flash("Eintrag gelöscht", "ok")
                elif action in ("approve_registration", "reject_registration") and pending_user_id:
                    if not is_request_approver():
                        flash("Nur der freigegebene Buchhalter darf Registrierungen bearbeiten.", "err")
                    else:
                        cur.execute(
                            "SELECT id, username, email, role, COALESCE(approval_status, 'approved') AS approval_status FROM users WHERE id=%s" if DATABASE_URL else
                            "SELECT id, username, email, role, COALESCE(approval_status, 'approved') AS approval_status FROM users WHERE id=?",
                            (pending_user_id,),
                        )
                        pending_user = cur.fetchone()
                        if not pending_user:
                            flash("Anfrage nicht gefunden.", "err")
                        elif row_value(pending_user, "approval_status", "approved") != "pending":
                            flash("Diese Anfrage wurde bereits bearbeitet.", "err")
                        else:
                            new_status = "approved" if action == "approve_registration" else "rejected"
                            approved_at_value = datetime.utcnow() if DATABASE_URL else _now_iso()
                            cur.execute(
                                "UPDATE users SET approval_status=%s, approved_at=%s, approved_by_email=%s WHERE id=%s" if DATABASE_URL else
                                "UPDATE users SET approval_status=?, approved_at=?, approved_by_email=? WHERE id=?",
                                (new_status, approved_at_value, normalize_email(session.get("email")), pending_user_id),
                            )
                            conn.commit()
                            if new_status == "approved":
                                try:
                                    send_registration_approved_email(
                                        normalize_email(row_value(pending_user, "email", "")),
                                        row_value(pending_user, "username", ""),
                                        row_value(pending_user, "role", "reisefuehrer"),
                                    )
                                    flash("Registrierung freigegeben und E-Mail versendet.", "ok")
                                except Exception as exc:
                                    app.logger.exception("Approval confirmation e-mail could not be sent for user %s", pending_user_id)
                                    flash(f"Registrierung freigegeben, aber die Bestätigungs-E-Mail konnte nicht versendet werden: {exc}", "err")
                            else:
                                flash("Registrierungsanfrage wurde abgelehnt und bleibt blockiert.", "ok")
            finally:
                conn.close()
            return redirect(url_for("dashboard", user_id=request.args.get("user_id", ""), monat=request.args.get("monat", ""), reise=request.args.get("reise", "")))

        conn = get_db()
        cur = conn.cursor()
        try:
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
                        (uid, betrag, wechselkurs_beleg),
                    )
                else:
                    cur.execute("SELECT wechselkurs_beleg FROM startguthaben WHERE user_id=?", (uid,))
                    existing = cur.fetchone()
                    existing_beleg = row_value(existing, "wechselkurs_beleg", existing[0] if existing else None)
                    cur.execute(
                        "INSERT OR REPLACE INTO startguthaben (user_id, betrag_sar, wechselkurs_beleg) VALUES (?,?,?)",
                        (uid, betrag, wechselkurs_beleg or existing_beleg),
                    )
                conn.commit()
                flash("Anfangsbestand gespeichert", "ok")
                return redirect(url_for("dashboard", monat=request.args.get("monat", ""), reise=request.args.get("reise", "")))

            if action == "reset_start":
                cur.execute(
                    "DELETE FROM startguthaben WHERE user_id=%s" if DATABASE_URL else
                    "DELETE FROM startguthaben WHERE user_id=?",
                    (uid,),
                )
                conn.commit()
                flash("Anfangsbestand zurückgesetzt", "ok")
                return redirect(url_for("dashboard", monat=request.args.get("monat", ""), reise=request.args.get("reise", "")))

            if action == "add_vorschuss":
                datum = request.form.get("vorschuss_datum") or datetime.utcnow().strftime("%Y-%m-%d")
                reise_name = normalize_trip_name(request.form.get("vorschuss_reise"))
                beschreibung = (request.form.get("vorschuss_beschreibung") or "").strip()
                betrag = _parse_decimal(request.form.get("vorschuss_betrag_sar", "0"))
                beleg_filename = None
                beleg_file = request.files.get("vorschuss_beleg")
                if beleg_file and beleg_file.filename:
                    fname = secure_filename(beleg_file.filename)
                    beleg_filename = f"{uuid.uuid4().hex}_{fname}"
                    beleg_file.save(os.path.join(app.config["UPLOAD_FOLDER"], beleg_filename))
                if betrag <= 0:
                    flash("Bitte einen gültigen Vorschussbetrag eingeben.", "err")
                    return redirect(url_for("dashboard", monat=request.args.get("monat", ""), reise=request.args.get("reise", "")))
                if DATABASE_URL:
                    cur.execute(
                        "INSERT INTO vorschuesse (user_id, datum, reise_name, beschreibung, betrag_sar, beleg, created_at) VALUES (%s,%s,%s,%s,%s,%s,NOW())",
                        (uid, datum, reise_name, beschreibung, betrag, beleg_filename),
                    )
                else:
                    cur.execute(
                        "INSERT INTO vorschuesse (user_id, datum, reise_name, beschreibung, betrag_sar, beleg, created_at) VALUES (?,?,?,?,?,?,?)",
                        (uid, datum, reise_name, beschreibung, betrag, beleg_filename, _now_iso()),
                    )
                conn.commit()
                flash("Vorschuss gespeichert", "ok")
                return redirect(url_for("dashboard", monat=request.args.get("monat", ""), reise=request.args.get("reise", "")))

            if action == "delete_vorschuss":
                vid = request.form.get("vid")
                if vid:
                    cur.execute(
                        "DELETE FROM vorschuesse WHERE id=%s AND user_id=%s" if DATABASE_URL else
                        "DELETE FROM vorschuesse WHERE id=? AND user_id=?",
                        (vid, uid),
                    )
                    conn.commit()
                    flash("Vorschuss gelöscht", "ok")
                return redirect(url_for("dashboard", monat=request.args.get("monat", ""), reise=request.args.get("reise", "")))

            if action == "add_kosten":
                datum = request.form.get("datum")
                kategorie_ar = request.form.get("kategorie")
                kategorie_de = CATEGORIES.get(kategorie_ar, {}).get("de")
                beschreibung_ar = (request.form.get("beschreibung_ar") or "").strip()
                beschreibung_de = "" if contains_arabic(beschreibung_ar) else beschreibung_ar
                betrag = _parse_decimal(request.form.get("betrag_sar", "0"))
                reise_name = normalize_trip_name(request.form.get("reise_name"))
                ohne_beleg = True if (DATABASE_URL and request.form.get("ohne_beleg")) else (1 if request.form.get("ohne_beleg") else 0)

                beleg_filename = None
                beleg_file = request.files.get("beleg")
                if beleg_file and beleg_file.filename:
                    fname = secure_filename(beleg_file.filename)
                    beleg_filename = f"{uuid.uuid4().hex}_{fname}"
                    beleg_file.save(os.path.join(app.config["UPLOAD_FOLDER"], beleg_filename))

                if ohne_beleg == 0 and not beleg_filename:
                    flash("Bitte Beleg hochladen oder 'بدون إيصال' aktivieren.", "err")
                    return redirect(url_for("dashboard", monat=request.args.get("monat", ""), reise=request.args.get("reise", "")))

                if DATABASE_URL:
                    cur.execute(
                        """
                        INSERT INTO kosten (
                            user_id, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de,
                            betrag_sar, beleg, ohne_beleg, genehmigt, created_at, reise_name
                        )
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,0,NOW(),%s)
                        """,
                        (uid, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de, betrag, beleg_filename, ohne_beleg, reise_name),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO kosten (
                            user_id, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de,
                            betrag_sar, beleg, ohne_beleg, genehmigt, created_at, reise_name
                        )
                        VALUES (?,?,?,?,?,?,?,?,?,0,?,?)
                        """,
                        (uid, datum, kategorie_ar, kategorie_de, beschreibung_ar, beschreibung_de, betrag, beleg_filename, ohne_beleg, _now_iso(), reise_name),
                    )
                conn.commit()
                flash("Ausgabe gespeichert", "ok")
                return redirect(url_for("dashboard", monat=request.args.get("monat", ""), reise=request.args.get("reise", "")))

            if action == "delete_kosten":
                kid = request.form.get("kid")
                if kid:
                    cur.execute(
                        "DELETE FROM kosten WHERE id=%s AND user_id=%s AND genehmigt=0" if DATABASE_URL else
                        "DELETE FROM kosten WHERE id=? AND user_id=? AND genehmigt=0",
                        (kid, uid),
                    )
                    conn.commit()
                    flash("Gelöscht", "ok")
                return redirect(url_for("dashboard", monat=request.args.get("monat", ""), reise=request.args.get("reise", "")))
        finally:
            conn.close()

        return redirect(url_for("dashboard", monat=request.args.get("monat", ""), reise=request.args.get("reise", "")))

    month_filter = (request.args.get("monat") or "").strip()
    trip_filter = normalize_trip_name(request.args.get("reise"))

    conn = get_db()
    cur = conn.cursor()
    try:
        if role == "buchhaltung":
            users = fetch_users(cur)
            selected_user_id_raw = (request.args.get("user_id") or "").strip()
            selected_user_id = int(selected_user_id_raw) if selected_user_id_raw.isdigit() else None

            kosten_all = fetch_kosten(cur, include_username=True)
            vorschuesse_all = fetch_vorschuesse(cur, include_username=True)
            if selected_user_id:
                kosten_all = [row for row in kosten_all if row["user_id"] == selected_user_id]
                vorschuesse_all = [row for row in vorschuesse_all if row["user_id"] == selected_user_id]

            trip_options = unique_trip_names(kosten_all, vorschuesse_all)
            filtered_kosten = [row for row in kosten_all if entry_matches_filters(row, month_filter, trip_filter)]
            filtered_vorschuesse = [row for row in vorschuesse_all if entry_matches_filters(row, month_filter, trip_filter)]
            missing_translation_count = sum(
                1 for row in filtered_kosten
                if translation_is_missing_or_not_german(row.get("beschreibung_ar"), row.get("beschreibung_de"))
            )

            start_map = {user["id"]: fetch_startbetrag(cur, user["id"]) for user in users}
            users_summary = []
            for user in users:
                user_start = start_map.get(user["id"], 0.0)
                user_kosten = fetch_kosten(cur, user_id=user["id"], include_username=True)
                user_vorschuesse = fetch_vorschuesse(cur, user_id=user["id"], include_username=True)
                adv_total = sum(row["betrag_sar"] for row in user_vorschuesse)
                exp_total = sum(row["betrag_sar"] for row in user_kosten if row.get("genehmigt") != -1)
                users_summary.append({
                    "id": user["id"],
                    "username": user["username"],
                    "start": user_start,
                    "vorschuesse": adv_total,
                    "total": exp_total,
                    "saldo": user_start + adv_total - exp_total,
                })

            visible_user_ids = [selected_user_id] if selected_user_id else [user["id"] for user in users]
            scope_summary = aggregate_summaries(visible_user_ids, start_map, kosten_all, vorschuesse_all, month_filter, trip_filter)
            can_manage_requests = is_request_approver()
            pending_registrations = fetch_pending_registrations(cur) if can_manage_requests else []

            return render_template(
                "admin.html",
                users_summary=users_summary,
                kosten=filtered_kosten,
                vorschuesse=filtered_vorschuesse,
                trip_options=trip_options,
                selected_month=month_filter,
                selected_trip=trip_filter,
                selected_user_id=selected_user_id_raw,
                users=users,
                scope_summary=scope_summary,
                can_manage_requests=can_manage_requests,
                pending_registrations=pending_registrations,
                approver_email=APPROVER_EMAIL,
                missing_translation_count=missing_translation_count,
            )

        start_amount = fetch_startbetrag(cur, uid)
        wechselkurs_beleg = fetch_wechselkurs_beleg(cur, uid)
        kosten_rows = fetch_kosten(cur, user_id=uid)
        vorschuesse_rows = fetch_vorschuesse(cur, user_id=uid)
        trip_options = unique_trip_names(kosten_rows, vorschuesse_rows)
        scope_summary = compute_scope_summary(start_amount, kosten_rows, vorschuesse_rows, month_filter, trip_filter)

        return render_template(
            "dashboard.html",
            ordered=list(CATEGORIES.items()),
            today=datetime.utcnow().strftime("%Y-%m-%d"),
            start=start_amount,
            opening=scope_summary["opening"],
            vorschuss_total=scope_summary["vorschuss_total"],
            total=scope_summary["kosten_total"],
            saldo=scope_summary["closing"],
            rows=scope_summary["filtered_kosten"],
            vorschuesse=scope_summary["filtered_vorschuesse"],
            wechselkurs_beleg=wechselkurs_beleg,
            trip_options=trip_options,
            selected_month=month_filter,
            selected_trip=trip_filter,
        )
    finally:
        conn.close()


@app.route("/export_excel")
def export_excel():
    if "user_id" not in session:
        return redirect(url_for("login"))

    role = session.get("role", "reisefuehrer")
    month_filter = (request.args.get("monat") or "").strip()
    trip_filter = normalize_trip_name(request.args.get("reise"))
    selected_user_id_raw = (request.args.get("user_id") or "").strip()
    selected_user_id = int(selected_user_id_raw) if selected_user_id_raw.isdigit() else None

    conn = get_db()
    cur = conn.cursor()
    try:
        if role == "buchhaltung":
            users = fetch_users(cur)
            start_map = {user["id"]: fetch_startbetrag(cur, user["id"]) for user in users}
            kosten_rows = fetch_kosten(cur, include_username=True)
            vorschuesse_rows = fetch_vorschuesse(cur, include_username=True)
            if selected_user_id:
                kosten_rows = [row for row in kosten_rows if row["user_id"] == selected_user_id]
                vorschuesse_rows = [row for row in vorschuesse_rows if row["user_id"] == selected_user_id]
                visible_user_ids = [selected_user_id]
                title_user = next((u["username"] for u in users if u["id"] == selected_user_id), f"user-{selected_user_id}")
            else:
                visible_user_ids = [user["id"] for user in users]
                title_user = "alle"
            summary = aggregate_summaries(visible_user_ids, start_map, kosten_rows, vorschuesse_rows, month_filter, trip_filter)
            filtered_kosten = [row for row in kosten_rows if entry_matches_filters(row, month_filter, trip_filter)]
            filtered_vorschuesse = [row for row in vorschuesse_rows if entry_matches_filters(row, month_filter, trip_filter)]
        else:
            title_user = session.get("username", "reisefuehrer")
            start_amount = fetch_startbetrag(cur, session["user_id"])
            kosten_rows = fetch_kosten(cur, user_id=session["user_id"])
            vorschuesse_rows = fetch_vorschuesse(cur, user_id=session["user_id"])
            summary_data = compute_scope_summary(start_amount, kosten_rows, vorschuesse_rows, month_filter, trip_filter)
            summary = {
                "opening": summary_data["opening"],
                "vorschuss_total": summary_data["vorschuss_total"],
                "kosten_total": summary_data["kosten_total"],
                "closing": summary_data["closing"],
            }
            filtered_kosten = summary_data["filtered_kosten"]
            filtered_vorschuesse = summary_data["filtered_vorschuesse"]

        output = io.StringIO()
        writer = csv.writer(output, delimiter=';')
        writer.writerow(["Reisekosten-Bericht"])
        writer.writerow(["Benutzer", title_user])
        writer.writerow(["Monat", month_filter or "alle"])
        writer.writerow(["Reise", trip_filter or "alle"])
        writer.writerow([])
        writer.writerow(["Kennzahl", "Betrag (SAR)"])
        writer.writerow(["Anfangssaldo", f"{summary['opening']:.2f}"])
        writer.writerow(["Vorschuesse", f"{summary['vorschuss_total']:.2f}"])
        writer.writerow(["Ausgaben", f"{summary['kosten_total']:.2f}"])
        writer.writerow(["Restguthaben", f"{summary['closing']:.2f}"])
        writer.writerow([])
        writer.writerow(["Vorschüsse"])
        writer.writerow(["ID", "Reiseführer", "Datum", "Reise", "Beschreibung", "Betrag (SAR)", "Beleg"])
        for row in filtered_vorschuesse:
            writer.writerow([
                row.get("id"),
                row.get("username") or title_user,
                row.get("datum"),
                row.get("reise_name") or "",
                row.get("beschreibung") or "",
                f"{row.get('betrag_sar', 0):.2f}",
                row.get("beleg") or "",
            ])
        writer.writerow([])
        writer.writerow(["Ausgaben"])
        writer.writerow(["ID", "Reiseführer", "Datum", "Reise", "Kategorie", "Beschreibung (Deutsch)", "Betrag (SAR)", "Status", "Beleg"])
        for row in filtered_kosten:
            writer.writerow([
                row.get("id"),
                row.get("username") or title_user,
                row.get("datum"),
                row.get("reise_name") or "",
                row.get("kategorie_de") or row.get("kategorie_ar") or "",
                row.get("beschreibung_de") or row.get("beschreibung_ar") or "",
                f"{row.get('betrag_sar', 0):.2f}",
                _status_text(int(row.get("genehmigt", 0) or 0)),
                row.get("beleg") or "",
            ])

        file_parts = ["reisekosten_bericht", title_user]
        if month_filter:
            file_parts.append(month_filter)
        if trip_filter:
            file_parts.append(trip_filter.replace(" ", "_"))
        filename = "_".join(file_parts) + ".csv"

        csv_bytes = output.getvalue().encode("utf-8-sig")
        return (csv_bytes, 200, {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": f"attachment; filename={filename}"
        })
    finally:
        conn.close()

# =========================
# ✅ NEU: Komplettes Backup (DB + uploads) als ZIP
# =========================
@app.route("/admin/export-backup")
def export_backup():
    if session.get("role") != "buchhaltung":
        flash("Keine Berechtigung.", "error")
        return redirect(url_for("dashboard"))

    ts = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    zip_name = f"reisekosten_backup_{ts}.zip"
    zip_path = os.path.join(tempfile.gettempdir(), zip_name)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        # 1) DB sichern
        if DATABASE_URL:
            # Bei Postgres ohne Shell: CSV-Exports der Tabellen
            conn = get_db()
            cur = conn.cursor()

            for table in ("users", "kosten", "startguthaben", "vorschuesse"):
                try:
                    cur.execute(f"SELECT * FROM {table}")
                    rows = cur.fetchall() or []
                except Exception:
                    rows = []

                csv_path = os.path.join(tempfile.gettempdir(), f"{table}_{ts}.csv")
                with open(csv_path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f, delimiter=";")
                    if rows and hasattr(rows[0], "keys"):
                        writer.writerow(rows[0].keys())
                        for r in rows:
                            writer.writerow(list(r.values()))
                    else:
                        # falls leer oder anderer Cursor-Typ
                        writer.writerow(["info"])
                        writer.writerow([f"Keine Daten oder kein Zugriff auf Tabelle {table}."])

                zipf.write(csv_path, arcname=f"database/{table}.csv")

            conn.close()
        else:
            # SQLite: komplette Datei
            if os.path.exists("reisekosten.db"):
                zipf.write("reisekosten.db", arcname="database/reisekosten.db")

        # 2) Uploads sichern
        upload_dir = app.config["UPLOAD_FOLDER"]
        if os.path.exists(upload_dir):
            for root, _, files in os.walk(upload_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, upload_dir)
                    zipf.write(full_path, arcname=f"uploads/{rel_path}")

    return send_file(zip_path, as_attachment=True)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        flash("Bitte zuerst einloggen.")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "DELETE FROM users WHERE id = %s" if DATABASE_URL else
            "DELETE FROM users WHERE id = ?",
            (user_id,)
        )
        conn.commit()
    finally:
        conn.close()

    session.clear()
    flash("Dein Account wurde gelöscht. Du kannst dich neu registrieren.")
    return redirect(url_for("register"))


@app.route("/buchhaltung/reisefuehrer_loeschen/<int:user_id>", methods=["POST"])
def buchhalter_delete_guide(user_id):
    # Nur Buchhaltung darf löschen
    if session.get("role") != "buchhaltung":
        flash("Keine Berechtigung.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cur = conn.cursor()
    try:
        # Alle Ausgaben/Einträge dieses Reiseführers löschen
        cur.execute(
            "DELETE FROM kosten WHERE user_id = %s" if DATABASE_URL else
            "DELETE FROM kosten WHERE user_id = ?",
            (user_id,)
        )
        # Startguthaben ebenfalls löschen (falls vorhanden)
        cur.execute(
            "DELETE FROM startguthaben WHERE user_id = %s" if DATABASE_URL else
            "DELETE FROM startguthaben WHERE user_id = ?",
            (user_id,)
        )
        # Vorschüsse ebenfalls löschen
        cur.execute(
            "DELETE FROM vorschuesse WHERE user_id = %s" if DATABASE_URL else
            "DELETE FROM vorschuesse WHERE user_id = ?",
            (user_id,)
        )
        # User löschen (nur Reiseführer)
        cur.execute(
            "DELETE FROM users WHERE id = %s AND role = %s" if DATABASE_URL else
            "DELETE FROM users WHERE id = ? AND role = ?",
            (user_id, "reisefuehrer")
        )
        conn.commit()
    finally:
        conn.close()

    flash("Reiseführer und alle Ausgaben wurden gelöscht. Benutzername/E-Mail sind wieder frei.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/restore-belege", methods=["POST"])
def restore_belege():
    # 🔐 Nur Buchhaltung
    if session.get("role") != "buchhaltung":
        flash("Keine Berechtigung.", "error")
        return redirect(url_for("dashboard"))

    file = request.files.get("backup_zip")
    if not file or not file.filename.lower().endswith(".zip"):
        flash("Bitte eine gültige ZIP-Datei auswählen.", "err")
        return redirect(url_for("dashboard"))

    upload_dir = app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)

    try:
        with zipfile.ZipFile(file) as zipf:
            restored = 0

            for member in zipf.infolist():
                name = member.filename

                # 🔒 Sicherheitschecks
                if not name.startswith("uploads/"):
                    continue
                if ".." in name or name.endswith("/"):
                    continue

                filename = os.path.basename(name)
                if not filename:
                    continue

                target_path = os.path.join(upload_dir, filename)

                # Datei schreiben (überschreibt ggf. alte Datei gleichen Namens)
                with zipf.open(member) as source, open(target_path, "wb") as target:
                    target.write(source.read())

                restored += 1

        flash(f"✅ {restored} Beleg-Dateien erfolgreich wiederhergestellt.", "ok")

    except Exception as e:
        flash(f"Fehler beim Wiederherstellen: {e}", "err")

    return redirect(url_for("dashboard"))



