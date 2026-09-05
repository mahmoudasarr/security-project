import os
import sys
import sqlite3
import socket
import ipaddress
import subprocess
import urllib.request
from urllib.parse import urlparse
from flask import Flask, request, render_template_string

app = Flask(__name__)

DB_FILE = "users.db"
COMMENTS = []
ACCOUNT = {"email": "victim@example.com"}


def init_db():
    # Create the database and a test user if it does not exist.
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
        conn.execute("INSERT INTO users VALUES ('admin', '123456')")
        conn.commit()
        conn.close()


@app.route("/")
def home():
    # Show the main menu with all vulnerability links.
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/read?file=app.py">/read</a> - Path Traversal</li>
        <li><a href="/fetch?url=http://example.com">/fetch</a> - SSRF</li>
        <li><a href="/ping?ip=127.0.0.1">/ping</a> - OS Command Injection</li>
        <li><a href="/login">/login</a> - SQL Injection</li>
        <li><a href="/debug">/debug</a> - Information Disclosure</li>
        <li><a href="/comments">/comments</a> - XSS</li>
        <li><a href="/greet?name=World">/greet</a> - SSTI</li>
        <li><a href="/account">/account</a> - CSRF</li>
    </ul>
    """


# 1. PATH TRAVERSAL -> FIXED
@app.route("/read")
def read_file():
    default_file = os.path.basename(__file__)
    filename = request.args.get("file", default_file)

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # FIXED: reject any absolute path or ".." traversal attempt, then
    # confirm the final resolved path is still inside base_dir.
    if filename.startswith("/") or ".." in filename:
        return "Invalid filename", 400

    file_path = os.path.realpath(os.path.join(base_dir, filename))
    if not file_path.startswith(base_dir + os.sep):
        return "Invalid filename", 400

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()

        return f"<h2>File Content</h2><pre>{content}</pre>"

    except Exception as e:
        return f"Error reading file: {str(e)}", 400


# Internal Admin Panel (Protected from direct browser access)
@app.route('/admin')
def admin_panel():
    # Check the visitor's identity via User-Agent
    user_agent = request.headers.get('User-Agent', '')
    
    # If the visitor is using a regular browser (Chrome, Firefox, etc.), deny access
    if 'Mozilla' in user_agent or 'Chrome' in user_agent:
        return "<h1>403 Forbidden</h1><p>Access Denied: Only internal server requests are trusted.</p>", 403
        
    # If the request is internal (via SSRF vulnerability using Python code), allow access
    return "<h3>Welcome to the Internal Admin Panel!</h3><p>Flag: FLAG{SSRF_Internal_Access_Success}</p>"


# 2. SSRF (Server-Side Request Forgery) -> FIXED
@app.route('/fetch')
def fetch_url():
    target_url = request.args.get('url', 'http://example.com')

    # FIXED: only allow http/https and block requests to private/internal
    # IP ranges (localhost, 169.254.x.x, 10.x.x.x, etc.) to stop SSRF.
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        return "Error fetching URL: scheme not allowed", 400

    try:
        ip = socket.gethostbyname(parsed.hostname)
        resolved_ip = ipaddress.ip_address(ip)
        if resolved_ip.is_private or resolved_ip.is_loopback \
                or resolved_ip.is_link_local or resolved_ip.is_reserved:
            return "Error fetching URL: internal addresses are blocked", 400
    except Exception as e:
        return f"Error fetching URL: {str(e)}", 400

    try:
        response = urllib.request.urlopen(target_url)
        content = response.read().decode('utf-8', errors='ignore')
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error fetching URL: {str(e)}", 400


# 3. OS COMMAND INJECTION -> FIXED
@app.route("/ping")
def ping():
    ip = request.args.get("ip", "127.0.0.1")

    # FIXED: validate that "ip" is really a valid IP address before using
    # it, and run ping via subprocess with a list of args (no shell=True),
    # so no extra commands can be injected.
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "Invalid IP address", 400

    output = subprocess.run(
        ["ping", "-c", "1", ip], capture_output=True, text=True
    ).stdout
    return f"<pre>{output}</pre>"