from flask import Flask, request, render_template_string, abort, session
from markupsafe import escape
import os
import re
import secrets
import ipaddress
import subprocess
import urllib.request
import sqlite3

app = Flask(__name__)

# Needed for session-based CSRF tokens. In a real app, load this from
# an environment variable / secrets manager instead of generating a
# new one on every restart.
app.secret_key = secrets.token_hex(32)

DB_FILE = "users.db"
COMMENTS = []

# Only used by the (fixed) SSRF demo: an explicit allow-list of hosts
# the server is permitted to fetch from.
ALLOWED_FETCH_HOSTS = {"example.com", "www.example.com"}

# Only used by the (fixed) account demo, in-memory for this example.
ACCOUNT = {"email": "victim@example.com"}


def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
        conn.execute("INSERT INTO users VALUES ('admin', '123456')")
        conn.commit()
        conn.close()


def get_csrf_token():
    """Create (or reuse) a per-session CSRF token."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def check_csrf_token():
    """Reject the request if the submitted token doesn't match the
    one stored in the user's session."""
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(submitted, expected):
        abort(403, description="Invalid or missing CSRF token.")


@app.route('/')
def home():
    return """
    <h2>Fixed App - Demo Routes</h2>
    <ul>
        <li><a href="/read?file=app_fixed.py">/read</a> - Path Traversal (fixed)</li>
        <li><a href="/fetch?url=http://example.com">/fetch</a> - SSRF (fixed)</li>
        <li><a href="/ping?ip=127.0.0.1">/ping</a> - OS Command Injection (fixed)</li>
        <li><a href="/login">/login</a> - SQL Injection (fixed)</li>
        <li><a href="/comments">/comments</a> - XSS (fixed)</li>
        <li><a href="/greet?name=World">/greet</a> - SSTI (fixed)</li>
        <li><a href="/account">/account</a> - CSRF (fixed)</li>
    </ul>
    """





# 4. SQL INJECTION — FIXED
# Use parameterized queries (placeholders) instead of building the
# SQL string with f-strings/concatenation, and store hashed passwords
# instead of plaintext.
from werkzeug.security import generate_password_hash, check_password_hash


def init_db_secure():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        conn.execute("CREATE TABLE users (username TEXT, password_hash TEXT)")
        conn.execute(
            "INSERT INTO users VALUES (?, ?)",
            ("admin", generate_password_hash("123456")),
        )
        conn.commit()
        conn.close()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        token = get_csrf_token()
        return f"""
        <h2>Login</h2>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{token}">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        """

    check_csrf_token()

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    conn = sqlite3.connect(DB_FILE)
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        return "Login successful!"
    return "Invalid credentials."

#-------------------------
# 5. INFORMATION DISCLOSURE — FIXED
# Debug endpoint removed entirely. If diagnostics are ever needed,
# they should be gated behind authentication + only enabled in a
# non-production environment, never exposed publicly. Flask's
# debug=True (which also leaks stack traces/allows code execution via
# the debugger) is disabled below in app.run() as well.
@app.route('/debug')
def debug_info():
    abort(404)


# 6. XSS — FIXED
# Escape any user-supplied content before inserting it into HTML, and
# require a CSRF token on the POST.
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    if request.method == 'POST':
        check_csrf_token()
        comment = request.form.get('comment', '')
        COMMENTS.append(comment)

    comments_html = ""
    for c in COMMENTS:
        comments_html += f"<p>{escape(c)}</p>"

    token = get_csrf_token()
    return f"""
    <h2>Comments</h2>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{token}">
        <input type="text" name="comment">
        <input type="submit" value="Post">
    </form>
    {comments_html}
    """


# 7. SSTI — FIXED
# Never build a Jinja2 template string out of user input. Pass the
# user's value as template *data* through the render context instead,
# and escape it (autoescaping also handles this by default in
# render_template_string for {{ }} expressions).
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    return render_template_string("<h2>Hello, {{ name }}!</h2>", name=name)


# 8. CSRF — FIXED
# Require a valid, per-session CSRF token on any state-changing POST.
# A cross-site page cannot read the token out of the victim's session,
# so it can't forge a valid request. (In production, also set the
# session cookie's SameSite attribute, e.g. SameSite=Lax/Strict, as
# defense in depth.)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


@app.route('/account', methods=['GET', 'POST'])
def account():
    if request.method == 'POST':
        check_csrf_token()
        new_email = request.form.get('email', '')
        ACCOUNT["email"] = new_email
        return f"<p>Email updated to: {escape(ACCOUNT['email'])}</p><a href='/account'>Back</a>"

    token = get_csrf_token()
    return f"""
    <h2>My Account</h2>
    <p>Current email: {escape(ACCOUNT['email'])}</p>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{token}">
        New email: <input type="text" name="email">
        <input type="submit" value="Update email">
    </form>
    """
#-------------------------

if __name__ == '__main__':
    init_db_secure()
    # debug=False in any environment reachable by untrusted users —
    # Flask's debugger allows remote code execution if left on.
    app.run(port=5000, debug=False)
