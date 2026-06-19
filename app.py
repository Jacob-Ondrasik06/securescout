from flask import Flask, render_template, request, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)

WAITLIST_FILE = "waitlist.json"


def load_waitlist():
    if os.path.exists(WAITLIST_FILE):
        with open(WAITLIST_FILE, "r") as f:
            return json.load(f)
    return []


def save_waitlist(data):
    with open(WAITLIST_FILE, "w") as f:
        json.dump(data, f, indent=2)


@app.route("/")
def index():
    waitlist = load_waitlist()
    return render_template("index.html", signups=len(waitlist))


@app.route("/join", methods=["POST"])
def join():
    data = request.get_json()
    email = data.get("email", "").strip().lower()

    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Please enter a valid email."})

    waitlist = load_waitlist()

    if any(e["email"] == email for e in waitlist):
        return jsonify({"success": False, "message": "You're already on the list!"})

    waitlist.append({"email": email, "joined": datetime.utcnow().isoformat()})
    save_waitlist(waitlist)

    return jsonify({"success": True, "message": f"You're in! {len(waitlist)} people on the waitlist."})


if __name__ == "__main__":
    app.run(debug=True)
