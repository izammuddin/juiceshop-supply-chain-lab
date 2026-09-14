"""
vulnerable_app.py
------------------
INTENTIONALLY VULNERABLE Flask application for training purposes ONLY.

This application contains deliberate security flaws. Do not deploy it,
expose it to a network beyond localhost, or reuse any pattern from it
in production code.

Setup:
    pip install flask
    python vulnerable_app.py
    # App runs on http://127.0.0.1:5000

Workshop use:
    Participants use AI tools to generate tests, review this code for
    vulnerabilities, and design malicious inputs against its endpoints.
"""

import sqlite3
import subprocess
from flask import Flask, request, g, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key-123"  # hardcoded secret (flaw)

DB_PATH = "workshop.db"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
    return db


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
        "password TEXT, role TEXT)"
    )
    # NOTE: passwords stored in plaintext (flaw)
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("alice", "alice123", "user"),
            ("bob", "bobpassword", "user"),
            ("admin", "admin_super_pw", "admin"),
        ],
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return jsonify({"service": "workshop-target-app", "status": "ok"})


@app.route("/login", methods=["POST"])
def login():
    """
    FLAW: builds SQL with string formatting -> classic SQL injection.
    Try submitting username = "admin' -- " with any password.
    """
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()
    cur = db.cursor()
    query = (
        f"SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    try:
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 400

    if row:
        return jsonify({"authenticated": True, "user_id": row[0], "role": row[2]})
    return jsonify({"authenticated": False}), 401


@app.route("/users/<int:user_id>")
def get_user(user_id):
    """
    FLAW: broken access control - no session/auth check at all.
    Any caller can fetch any user's record, including the admin's.
    """
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
    )
    row = cur.fetchone()
    if row:
        return jsonify({"id": row[0], "username": row[1], "role": row[2]})
    return jsonify({"error": "not found"}), 404


@app.route("/ping")
def ping():
    """
    FLAW: command injection - host parameter is passed straight to the shell.
    Try host = "127.0.0.1; ls" or similar.
    """
    host = request.args.get("host", "127.0.0.1")
    cmd = f"ping -c 1 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout, "error": result.stderr})


@app.route("/search")
def search():
    """
    FLAW: reflected input with no output encoding (would be XSS if rendered
    as HTML by a client). Also no input length/type validation.
    """
    term = request.args.get("q", "")
    # Simulate a "search results" response that echoes input unescaped.
    return f"<html><body>Results for: {term}</body></html>"


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
