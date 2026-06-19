import os
import json
import uuid
import psycopg2
from flask import Flask, render_template, request, jsonify, redirect, url_for
from dotenv import load_dotenv
from scanner.engine import run_scan
from mailer import send_email, build_report_email

load_dotenv()

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")


def get_db():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS waitlist (
                    id SERIAL PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    joined TIMESTAMP DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    result JSONB,
                    created TIMESTAMP DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS leads (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL,
                    scan_id TEXT,
                    url TEXT,
                    emailed BOOLEAN DEFAULT FALSE,
                    created TIMESTAMP DEFAULT NOW()
                )
            """)
        conn.commit()


try:
    init_db()
except Exception as e:
    print(f"[warn] init_db failed: {e}")


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/")
def index():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM waitlist")
            signups = cur.fetchone()[0]
    return render_template("index.html", signups=signups)


@app.route("/join", methods=["POST"])
def join():
    data = request.get_json()
    email = data.get("email", "").strip().lower()

    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Please enter a valid email."})

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO waitlist (email) VALUES (%s)", (email,))
            conn.commit()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM waitlist")
                count = cur.fetchone()[0]
        return jsonify({"success": True, "message": f"You're in! {count} people on the waitlist."})
    except psycopg2.errors.UniqueViolation:
        return jsonify({"success": False, "message": "You're already on the list!"})


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()
    if not url:
        return redirect(url_for("index"))

    if not url.startswith("http"):
        url = "https://" + url

    scan_id = str(uuid.uuid4())[:8]

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO scans (id, url) VALUES (%s, %s)", (scan_id, url))
        conn.commit()

    return render_template("loading.html", scan_id=scan_id, url=url)


@app.route("/scan/run/<scan_id>")
def scan_run(scan_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT url, result FROM scans WHERE id = %s", (scan_id,))
            row = cur.fetchone()

    if not row:
        return jsonify({"error": "Scan not found"}), 404

    url, result = row

    if result is None:
        result = run_scan(url)
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE scans SET result = %s WHERE id = %s",
                            (json.dumps(result), scan_id))
            conn.commit()

    return jsonify({"done": True, "scan_id": scan_id})


@app.route("/results/<scan_id>")
def results(scan_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT url, result FROM scans WHERE id = %s", (scan_id,))
            row = cur.fetchone()

    if not row or not row[1]:
        return redirect(url_for("index"))

    url, result = row
    return render_template("results.html", result=result, scan_id=scan_id)


@app.route("/email-results", methods=["POST"])
def email_results():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    scan_id = data.get("scan_id", "").strip()

    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Please enter a valid email."})

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT url, result FROM scans WHERE id = %s", (scan_id,))
            row = cur.fetchone()

    if not row or not row[1]:
        return jsonify({"success": False, "message": "Scan not found. Try running it again."})

    url, result = row

    # Capture the lead first — this is the part that matters for the business,
    # so it happens even if email delivery isn't configured yet.
    html = build_report_email(result, scan_id, BASE_URL)
    sent, _ = send_email(email, f"Your SecureScout report for {result['domain']}", html)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO leads (email, scan_id, url, emailed) VALUES (%s, %s, %s, %s)",
                (email, scan_id, url, sent),
            )
        conn.commit()

    if sent:
        return jsonify({"success": True, "message": "Sent! Check your inbox for the full report."})
    return jsonify({"success": True, "message": "Got it — your report is on the way."})


@app.route("/admin/leads")
def admin_leads():
    if not ADMIN_KEY or request.args.get("key") != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT email, url, emailed, created
                FROM leads ORDER BY created DESC LIMIT 500
            """)
            leads = [
                {"email": r[0], "url": r[1], "emailed": r[2], "created": r[3].isoformat()}
                for r in cur.fetchall()
            ]
            cur.execute("SELECT COUNT(*) FROM leads")
            total = cur.fetchone()[0]

    return jsonify({"total_leads": total, "leads": leads})
