"""
Demo Web Application - For Security Agent Code Review Testing
WARNING: This code contains intentional security vulnerabilities for demonstration purposes.
DO NOT use this code in production environments.
"""

import os
import sqlite3
import hashlib
import pickle
import subprocess
import logging
import tempfile
import requests
from flask import Flask, request, jsonify, render_template_string, redirect, session, make_response

app = Flask(__name__)

# BUG 1: Hardcoded secret key (CWE-798: Use of Hard-coded Credentials)
app.secret_key = "super_secret_key_12345"

# BUG 2: Hardcoded database credentials (CWE-798)
DB_HOST = "production-db.example.com"
DB_USER = "admin"
DB_PASSWORD = "P@ssw0rd123!"
API_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# BUG 3: Debug mode enabled (CWE-489: Active Debug Code)
DEBUG_MODE = True

# BUG 4: Insecure logging - logging sensitive data
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def get_db_connection():
    """Create database connection."""
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database."""
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


# =============================================
# BUG 5: SQL Injection (CWE-89)
# =============================================
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # Log sensitive information
    logger.info(f"Login attempt: username={username}, password={password}")  # BUG 6: Logging password

    conn = get_db_connection()
    # SQL Injection vulnerability - string concatenation in query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = conn.execute(query).fetchone()
    conn.close()

    if user:
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        return jsonify({"message": "Login successful", "role": user["role"]})
    return jsonify({"error": "Invalid credentials"}), 401


# =============================================
# BUG 7: Cross-Site Scripting / XSS (CWE-79)
# =============================================
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Directly embedding user input in HTML without sanitization
    html = f"""
    <html>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <p>No results found.</p>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/profile/<username>")
def profile(username):
    # Reflected XSS via URL parameter
    return f"<html><body><h1>Profile: {username}</h1></body></html>"


# =============================================
# BUG 8: Command Injection (CWE-78)
# =============================================
@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host")
    # Directly passing user input to shell command
    result = os.popen(f"ping -c 3 {host}").read()
    return jsonify({"output": result})


@app.route("/dns-lookup", methods=["POST"])
def dns_lookup():
    domain = request.form.get("domain")
    # Another command injection via subprocess with shell=True
    result = subprocess.run(
        f"nslookup {domain}",
        shell=True,  # BUG 9: shell=True with user input
        capture_output=True,
        text=True
    )
    return jsonify({"output": result.stdout})


# =============================================
# BUG 10: Insecure Deserialization (CWE-502)
# =============================================
@app.route("/import-data", methods=["POST"])
def import_data():
    data = request.get_data()
    # Deserializing untrusted data with pickle
    obj = pickle.loads(data)
    return jsonify({"message": "Data imported", "items": len(obj)})


# =============================================
# BUG 11: Path Traversal (CWE-22)
# =============================================
@app.route("/download")
def download_file():
    filename = request.args.get("file")
    # No validation on filename, allows directory traversal
    filepath = os.path.join("/app/uploads", filename)
    with open(filepath, "r") as f:
        content = f.read()
    return content


@app.route("/view-log")
def view_log():
    log_name = request.args.get("name")
    # Path traversal - user can read any file on the system
    with open(f"/var/log/{log_name}", "r") as f:
        return f.read()


# =============================================
# BUG 12: Weak Cryptography (CWE-328)
# =============================================
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")

    # Using MD5 for password hashing (weak, no salt)
    password_hash = hashlib.md5(password.encode()).hexdigest()

    conn = get_db_connection()
    # SQL injection here too
    conn.execute(
        f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password_hash}', '{email}')"
    )
    conn.commit()
    conn.close()

    logger.info(f"New user registered: {username}, email: {email}")
    return jsonify({"message": "User registered successfully"})


# =============================================
# BUG 13: Server-Side Request Forgery / SSRF (CWE-918)
# =============================================
@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    url = request.form.get("url")
    # No URL validation - allows SSRF to internal services
    response = requests.get(url)
    return jsonify({
        "status": response.status_code,
        "content": response.text[:1000]
    })


@app.route("/webhook", methods=["POST"])
def webhook():
    callback_url = request.json.get("callback_url")
    data = request.json.get("data")
    # SSRF via webhook callback
    requests.post(callback_url, json=data)
    return jsonify({"message": "Webhook delivered"})


# =============================================
# BUG 14: Insecure Direct Object Reference / IDOR (CWE-639)
# =============================================
@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    # No authorization check - any user can access any other user's data
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if user:
        return jsonify({
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "password": user["password"],  # BUG 15: Exposing password hash in API response
            "role": user["role"]
        })
    return jsonify({"error": "User not found"}), 404


# =============================================
# BUG 16: Missing Security Headers & CORS misconfiguration
# =============================================
@app.after_request
def add_headers(response):
    # Overly permissive CORS
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    # Missing security headers: no X-Content-Type-Options, no X-Frame-Options,
    # no Content-Security-Policy, no Strict-Transport-Security
    return response


# =============================================
# BUG 17: Insecure File Upload (CWE-434)
# =============================================
@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    if file:
        # No file type validation, no size limit, saving with original filename
        filename = file.filename  # BUG 18: No sanitization of filename
        file.save(os.path.join("/app/uploads", filename))
        return jsonify({"message": f"File {filename} uploaded successfully"})
    return jsonify({"error": "No file provided"}), 400


# =============================================
# BUG 19: Mass Assignment / Over-posting
# =============================================
@app.route("/api/user/update", methods=["PUT"])
def update_user():
    user_id = session.get("user_id")
    data = request.get_json()

    conn = get_db_connection()
    # Allows updating ANY field including 'role' - privilege escalation
    for key, value in data.items():
        conn.execute(f"UPDATE users SET {key} = '{value}' WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return jsonify({"message": "User updated"})


# =============================================
# BUG 20: Unvalidated Redirect (CWE-601)
# =============================================
@app.route("/redirect")
def open_redirect():
    target = request.args.get("url")
    # Open redirect - no validation of target URL
    return redirect(target)


# =============================================
# BUG 21: XML External Entity (XXE) Processing
# =============================================
@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    import xml.etree.ElementTree as ET
    xml_data = request.get_data()
    # Parsing XML without disabling external entities
    root = ET.fromstring(xml_data)
    return jsonify({"root_tag": root.tag, "text": root.text})


# =============================================
# BUG 22: Temporary file with insecure permissions
# =============================================
@app.route("/export", methods=["POST"])
def export_data():
    data = request.form.get("data")
    # Creating temp file with predictable name and insecure permissions
    tmp_file = f"/tmp/export_{request.form.get('name')}.csv"
    with open(tmp_file, "w") as f:
        f.write(data)
    os.chmod(tmp_file, 0o777)  # BUG 23: World-writable permissions
    return jsonify({"file": tmp_file})


# =============================================
# BUG 24: Insecure Cookie Settings
# =============================================
@app.route("/set-session")
def set_session():
    resp = make_response("Session set")
    resp.set_cookie(
        "session_token",
        "abc123xyz",
        httponly=False,  # Accessible via JavaScript
        secure=False,    # Sent over HTTP
        samesite=None    # No SameSite protection
    )
    return resp


# =============================================
# Main Entry Point
# =============================================
if __name__ == "__main__":
    init_db()
    # BUG 25: Running with debug=True and binding to all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
