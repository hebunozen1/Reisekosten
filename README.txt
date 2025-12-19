# Reisekosten Webapp (Final) – Login + Rollen + Übersicht

## Start (Windows / VS Code)
```powershell
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

## URLs
- Login: http://127.0.0.1:5000/login
- Reiseleiter Registrierung: http://127.0.0.1:5000/register

## Default Buchhaltung
- Username: alaa
- Passwort: alaa123

## Hinweis
- Übersetzung Arabisch -> Deutsch läuft über googletrans (kostenlos).
- Empfehlung: Python 3.11 verwenden (Python 3.14 ist aktuell nicht kompatibel mit googletrans/httpx).


## Deployment (Render)
- Add a PostgreSQL database in Render.
- Ensure your web service has the environment variable DATABASE_URL (Render sets it automatically when you link the DB).
- Start command: `gunicorn app:app` (also provided via Procfile).
- For local dev without DATABASE_URL, the app falls back to SQLite (`reisekosten.db`).
