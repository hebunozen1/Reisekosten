from __future__ import annotations

import os
import sqlite3
from datetime import timedelta
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
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('reisefuehrer','buchhaltung')),
        startguthaben_sar REAL DEFAULT 0
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

    row = db.execute("SELECT 1 FROM users WHERE role='buchhaltung' LIMIT 1").fetchone()
    if not row:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            ("alaa", generate_password_hash("alaa123"), "buchhaltung")
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
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", role).strip() or "reisefuehrer"
        remember = True if request.form.get("remember") else False

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        db.close()

        if user and check_password_hash(user["password_hash"], password):
            if user["role"] != role:
                flash("Falscher Login-Bereich (Rolle stimmt nicht).", "error")
                return render_template("login.html", role=role)

            session.clear()
            session.permanent = remember  # nur bei "angemeldet bleiben"
            session["user_id"] = int(user["id"])
            session["role"] = user["role"]
            session["username"] = user["username"]
            return redirect(url_for("admin" if user["role"] == "buchhaltung" else "dashboard"))

        flash("Login fehlgeschlagen. Bitte prüfen.", "error")

    return render_template("login.html", role=role)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        role = (request.form.get("role") or "reisefuehrer").strip().lower()
        if role not in ("reisefuehrer","buchhaltung"):
            role = "reisefuehrer"

        if not username or not password:
            flash("Bitte Username und Passwort eingeben.", "error")
            return render_template("register.html")
        if password != password2:
            flash("Passwörter stimmen nicht überein.", "error")
            return render_template("register.html")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, generate_password_hash(password), role),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username existiert bereits.", "error")
            db.close()
            return render_template("register.html")

        db.close()
        flash("Registrierung erfolgreich. Bitte einloggen.", "ok")
        return redirect(url_for("login", role="reisefuehrer"))

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
        if action == "set_start":
            wert = request.form.get("startguthaben_sar", "").strip()
            try:
                val = float(wert.replace(",", ".")) if wert else 0.0
            except ValueError:
                flash("Bitte eine gültige Zahl für den Betrag eingeben.", "error")
                db.close()
                return redirect(url_for("dashboard"))

        elif action == "reset_start":
            db.execute("UPDATE users SET startguthaben_sar=? WHERE id=?", (0.0, uid))
            db.commit()
            flash("Startguthaben wurde zurückgesetzt.", "ok")
            db.close()
            return redirect(url_for("dashboard"))

        elif action == "delete_kosten":
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

            if row["genehmigt"]:
                flash("Genehmigte Einträge können nicht gelöscht werden.", "error")
                db.close()
                return redirect(url_for("dashboard"))

            # optional: Belegdatei mitlöschen
            if row["beleg"]:
                try:
                    os.remove(os.path.join(app.config["UPLOAD_FOLDER"], row["beleg"]))
                except OSError:
                    pass

            db.execute("DELETE FROM kosten WHERE id=? AND user_id=?", (kid, uid))
            db.commit()
            flash("Eintrag gelöscht.", "ok")
            db.close()
            return redirect(url_for("dashboard"))

            db.execute("UPDATE users SET startguthaben_sar=? WHERE id=?", (val, uid))
            db.commit()
            flash("Betrag gespeichert.", "ok")
            db.close()
            return redirect(url_for("dashboard"))

        
        datum = request.form.get("datum", "")
        kat_code = request.form.get("kategorie", "")
        besch_ar = request.form.get("beschreibung_ar", "").strip()
        betrag_sar = request.form.get("betrag_sar", "").strip()

        if not datum or not kat_code or not besch_ar or not betrag_sar:
            flash("Bitte alle Pflichtfelder ausfüllen.", "error")
        else:
            try:
                betrag_sar_f = float(betrag_sar.replace(",", "."))
            except ValueError:
                flash("Betrag muss eine Zahl sein.", "error")
                betrag_sar_f = None

            if betrag_sar_f is not None:
                file = request.files.get("beleg")
                fname = None
                if file and file.filename:
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

    start = db.execute("SELECT startguthaben_sar FROM users WHERE id=?", (uid,)).fetchone()["startguthaben_sar"]
    rows = db.execute(
        """
        SELECT id, datum, kategorie_ar, beschreibung_ar, betrag_sar, genehmigt
        FROM kosten
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (uid,),
    ).fetchall()
    total = sum(float(r["betrag_sar"]) for r in rows) if rows else 0.0
    saldo = float(start) - float(total)

    ordered = [(k, KATEGORIEN[k]) for k in KATEGORIEN_ORDER]
    db.close()
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        kategorien=ordered,
        rows=rows,
        start=start,
        total=total,
        saldo=saldo,
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



@app.route("/uploads/<filename>")
@login_required()
def uploads(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
