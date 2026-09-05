from flask import Flask, request, render_template_string
import os
import urllib.request
import sys
import sqlite3

app = Flask(__name__)

DB_FILE = "users.db"
COMMENTS = []


# Creates the database and a test user, only if it doesn't exist yet.
def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
        conn.execute("INSERT INTO users VALUES ('admin', '123456')")
        conn.commit()
        conn.close()


@app.route("/")
def home():
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


# 1. PATH TRAVERSAL
@app.route("/read")
def read_file():
    file_name = request.args.get("file", "app.py")

    # Get folder path of this file, so it works from any folder.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, file_name)

    # VULNERABLE: file_name is used with no check.
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return f"<pre>{content}</pre>"


# 2. SSRF
@app.route("/fetch")
def fetch_url():
    target_url = request.args.get("url", "http://example.com")

    # VULNERABLE: server visits any URL with no check.
    response = urllib.request.urlopen(target_url)
    content = response.read().decode("utf-8", errors="ignore")
    return f"<pre>{content}</pre>"


@app.route("/admin")
def admin_panel():
    return "SECRET ADMIN PANEL: Only accessible internally!"


# 3. OS COMMAND INJECTION
@app.route("/ping")
def ping():
    ip = request.args.get("ip", "127.0.0.1")

    # VULNERABLE: user input goes straight into the command.
    command = "ping -c 1 " + ip
    output = os.popen(command).read()
    return f"<pre>{output}</pre>"


# 4. SQL INJECTION
@app.route("/login", methods=["GET", "POST"])
def login():
    # Show the login form on a normal GET request.
    if request.method == "GET":
        return """
        <h2>Login</h2>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        """

    # Handle the form submission (POST).
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABLE: username and password are glued directly into the
    # SQL query string, instead of being passed as safe parameters.
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    conn = sqlite3.connect(DB_FILE)
    result = conn.execute(query).fetchall()
    conn.close()

    if result:
        return "Login successful!"
    return "Invalid credentials."


# 5. INFORMATION DISCLOSURE
@app.route("/debug")
def debug_info():
    # VULNERABLE: exposes internal server details that should never
    # be visible to a normal visitor (file paths, environment, etc.)
    info = f"""
    <h3>Debug Info</h3>
    <p>App file location: {os.path.abspath(__file__)}</p>
    <p>Database file: {os.path.abspath(DB_FILE)}</p>
    <p>Current working directory: {os.getcwd()}</p>
    <p>Python version: {sys.version}</p>
    <p>Server OS: {os.name}</p>
    """
    return info


# 6. XSS (Cross-Site Scripting)
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        # Save whatever the user submits, exactly as typed.
        comment = request.form.get("comment", "")
        COMMENTS.append(comment)

    # Build the list of comments as raw HTML.
    comments_html = ""
    for c in COMMENTS:
        # VULNERABLE: the comment is inserted into the page with no
        # escaping, so any HTML/JS the user typed runs as real code.
        comments_html += f"<p>{c}</p>"

    return f"""
    <h2>Comments</h2>
    <form method="POST">
        <input type="text" name="comment">
        <input type="submit" value="Post">
    </form>
    {comments_html}
    """


# 7. SSTI (Server-Side Template Injection)
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")

    # VULNERABLE: user input is inserted directly into the template
    # string BEFORE it's rendered, so Jinja2 treats it as template
    # code, not just as text.
    template = f"<h2>Hello, {name}!</h2>"
    return render_template_string(template)


# 8. CSRF (Cross-Site Request Forgery)
#
# In-memory "logged in" user state, just for this demo.
ACCOUNT = {"email": "victim@example.com"}


@app.route("/account", methods=["GET", "POST"])
def account():
    if request.method == "POST":
        new_email = request.form.get("email", "")

        # VULNERABLE: this changes sensitive account data (the email)
        # based on nothing but a POST request. There is no CSRF token,
        # no check of the Origin/Referer header, and the session cookie
        # (if any) would be sent automatically by the browser on a
        # cross-site request too. Any page on the internet can make
        # the victim's browser submit this form while they're logged
        # in, and the change goes through.
        ACCOUNT["email"] = new_email
        return f"<p>Email updated to: {ACCOUNT['email']}</p><a href='/account'>Back</a>"

    return f"""
    <h2>My Account</h2>
    <p>Current email: {ACCOUNT['email']}</p>
    <form method="POST">
        New email: <input type="text" name="email">
        <input type="submit" value="Update email">
    </form>
    <hr>
    <p>Demo attacker page that exploits this: <a href="/csrf_demo">/csrf_demo</a></p>
    """


@app.route("/csrf_demo")
def csrf_demo():
    # This simulates a malicious third-party page. If a logged-in
    # victim simply visits this page, the form below auto-submits a
    # POST to /account and silently changes their email — no click,
    # no confirmation, no token check.
    return """
    <h3>Totally Harmless Page</h3>
    <p>This page silently changes your account email on the vulnerable app.</p>
    <form id="evil" action="/account" method="POST">
        <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>document.getElementById('evil').submit();</script>
    """


if __name__ == "__main__":
    init_db()
    app.run(port=5000, debug=True)
