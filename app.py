import os
import psycopg2
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")


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
        conn.commit()


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


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
