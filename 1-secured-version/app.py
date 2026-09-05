import os
import sys
import sqlite3
import socket
import secrets
import ipaddress
import subprocess
import urllib.request
from urllib.parse import urlparse
from flask import Flask, request, render_template_string, session, abort

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

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

    # FIXED: reject any absolute path, ".." traversal attempt, or null
    # byte, then confirm the final resolved path is still inside base_dir.
    if filename.startswith("/") or ".." in filename or "\x00" in filename:
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


# 4. SQL INJECTION -> FIXED
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Show the login page.
        return """
        <h2>Login</h2>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        """

    # Get data from the form.
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # FIXED: use a parameterized query instead of building the SQL string
    # with f-strings, so user input can never break out of the query.
    query = "SELECT * FROM users WHERE username=? AND password=?"

    conn = sqlite3.connect(DB_FILE)
    result = conn.execute(query, (username, password)).fetchall()
    conn.close()

    if result:
        return "Login successful!"
    return "Invalid credentials."


# 5. INFORMATION DISCLOSURE -> FIXED
@app.route("/debug")
def debug_info():
    # FIXED: the route used to leak the app path, database path, current
    # directory, Python version, and server OS. That kind of internal
    # information should never be exposed, so the route is disabled.
    abort(404)


# 6. XSS (Cross-Site Scripting) -> FIXED
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        # Get the comment from the user.
        comment = request.form.get("comment", "")
        COMMENTS.append(comment)

    # FIXED: use render_template_string with Jinja2 {{ }} placeholders
    # instead of an f-string, so Jinja2's autoescaping neutralizes any
    # HTML/JS the user submits instead of rendering it as raw HTML.
    return render_template_string("""
    <h2>Comments</h2>
    <form method="POST">
        <input type="text" name="comment">
        <input type="submit" value="Post">
    </form>
    {% for c in comments %}
    <p>{{ c }}</p>
    {% endfor %}
    """, comments=COMMENTS)


# 7. SSTI (Server-Side Template Injection) -> FIXED
@app.route("/greet")
def greet():
    # Get the name from the URL.
    name = request.args.get("name", "World")

    # FIXED: keep the template string fixed/constant and pass "name" in
    # as a Jinja2 variable instead of splicing it into the template text
    # with an f-string. This way user input is only ever treated as data,
    # never as template code, so "{{ }}" payloads can't execute.
    template = "<h2>Hello, {{ name }}!</h2>"
    return render_template_string(template, name=name)


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


# 8. CSRF (Cross-Site Request Forgery) -> FIXED
@app.route("/account", methods=["GET", "POST"])
def account():
    if request.method == "POST":
        # FIXED: require a CSRF token tied to the user's own session.
        # A forged request from another site (like /csrf_demo) cannot
        # know this token, so the request is rejected.
        submitted_token = request.form.get("csrf_token", "")
        if not submitted_token or submitted_token != session.get("csrf_token"):
            abort(403, description="Invalid CSRF token")

        # Get the new email from the form.
        new_email = request.form.get("email", "")
        ACCOUNT["email"] = new_email
        return f"<p>Email updated to: {ACCOUNT['email']}</p><a href='/account'>Back</a>"

    # Show the account page.
    token = get_csrf_token()
    return f"""
    <h2>My Account</h2>
    <p>Current email: {ACCOUNT['email']}</p>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{token}">
        New email: <input type="text" name="email">
        <input type="submit" value="Update email">
    </form>
    <hr>
    <p>Demo attacker page: <a href="/csrf_demo">/csrf_demo</a></p>
    """


@app.route("/csrf_demo")
def csrf_demo():
    # This is a fake attacker page. It tries to change the user's email
    # automatically, but it has no way to know the real csrf_token, so
    # /account will now reject this forged request with 403.
    return """
    <h3>Totally Harmless Page</h3>
    <p>This page tries to silently change your account email.</p>
    <form id="evil" action="/account" method="POST">
        <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>document.getElementById('evil').submit();</script>
    """


if __name__ == "__main__":
    init_db()
    app.run(port=5000, debug=False)