from flask import Flask, request, abort
from markupsafe import escape
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
import urllib.request
import ipaddress
import socket
import re
import subprocess
import os
import sqlite3

app = Flask(__name__)

# =========================================================
# Shared home page
# =========================================================
@app.route('/')
def home():
    return """
    <h2>Fixed App - SSRF / Command Injection / SQL Injection</h2>
    <ul>
        <li><a href="/fetch?url=http://example.com">/fetch</a> - SSRF (fixed)</li>
        <li><a href="/ping?ip=127.0.0.1">/ping</a> - OS Command Injection (fixed)</li>
        <li><a href="/login">/login</a> - SQL Injection (fixed)</li>
    </ul>
    """


# =========================================================
# 2. SSRF — FIXED
# =========================================================
ALLOWED_FETCH_HOSTS = {"example.com", "www.example.com"}


@app.route('/fetch')
def fetch_url():
    target_url = request.args.get('url', 'http://example.com')
    parsed = urlparse(target_url)

    # 1) Only allow http/https.
    if parsed.scheme not in ("http", "https"):
        abort(400, description="Only http/https URLs are allowed.")

    # 2) Allow-list the hostname (blocks arbitrary internal/external targets).
    if parsed.hostname not in ALLOWED_FETCH_HOSTS:
        abort(403, description="This host is not on the allow-list.")

    # 3) Resolve the hostname and refuse private/loopback/link-local IPs
    #    (defends against DNS rebinding to internal services).
    try:
        resolved_ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(resolved_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            abort(403, description="Refusing to fetch internal/private addresses.")
    except (socket.gaierror, ValueError):
        abort(400, description="Could not resolve host.")

    response = urllib.request.urlopen(target_url, timeout=5)
    content = response.read(1_000_000).decode('utf-8', errors='ignore')
    return f"<pre>{escape(content)}</pre>"


# =========================================================
# 3. OS COMMAND INJECTION — FIXED
# =========================================================
HOSTNAME_RE = re.compile(r'^[A-Za-z0-9.\-]+$')


@app.route('/ping')
def ping():
    ip = request.args.get('ip', '127.0.0.1')

    # 1) Validate the input is a real IP address, or a hostname made
    #    only of safe characters — reject anything else (no shell
    #    metacharacters like ; | & $ ` etc. can sneak through).
    is_valid_ip = False
    try:
        ipaddress.ip_address(ip)
        is_valid_ip = True
    except ValueError:
        pass

    if not is_valid_ip and not HOSTNAME_RE.match(ip):
        abort(400, description="Invalid IP address or hostname.")

    # 2) Pass arguments as a list to subprocess, never build a shell
    #    string, and never use shell=True.
    try:
        result = subprocess.run(
            ["ping", "-c", "1", ip],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Request timed out."

    return f"<pre>{escape(output)}</pre>"


# =========================================================
# 4. SQL INJECTION — FIXED
# =========================================================
DB_FILE = "users_fixed.db"


def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        conn.execute("CREATE TABLE users (username TEXT, password_hash TEXT)")
        # Never store plaintext passwords — hash them.
        conn.execute(
            "INSERT INTO users VALUES (?, ?)",
            ("admin", generate_password_hash("123456")),
        )
        conn.commit()
        conn.close()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return """
        <h2>Login</h2>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        """

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Parameterized query — the driver keeps user input as *data*,
    # never as part of the SQL syntax, so injection is impossible.
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        return "Login successful!"
    return "Invalid credentials."


if __name__ == '__main__':
    init_db()
    app.run(port=5000, debug=False)
