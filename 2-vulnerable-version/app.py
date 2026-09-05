import os
import sys
import sqlite3
import urllib.request
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


# 1. PATH TRAVERSAL
@app.route("/read")
def read_file():
    # Automatically use the name of the current file (even if it is not called app.py)
    default_file = os.path.basename(__file__)
    filename = request.args.get("file", default_file)

    # Select the full path of the folder to ensure that the files are read successfully
    if filename.startswith("/"):
        file_path = filename
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = base_dir + "/" + filename

    try:
        # VULNERABLE: The user controls the file path directly.
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


# 2. SSRF (Server-Side Request Forgery)
@app.route('/fetch')
def fetch_url():
    # Get the URL from the user.
    target_url = request.args.get('url', 'http://example.com')
    try:
        # VULNERABLE: The server visits any URL without checking it.
        # Internal Python requests send a different User-Agent and do not contain 'Mozilla'
        response = urllib.request.urlopen(target_url)
        content = response.read().decode('utf-8', errors='ignore')
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error fetching URL: {str(e)}", 400


# 3. OS COMMAND INJECTION
@app.route("/ping")
def ping():
    # Get the IP address from the URL.
    ip = request.args.get("ip", "127.0.0.1")

    # VULNERABLE: The app puts the IP directly into the command.
    # An attacker can add more commands using ';' or '&&'.
    command = "ping -c 1 " + ip
    output = os.popen(command).read()
    return f"<pre>{output}</pre>"


# 4. SQL INJECTION
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

    # VULNERABLE: We put the username and password directly into the SQL query.
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
    # VULNERABLE: The app shows secret system information.
    info = f"""
    <h3>Debug Info</h3>
    <p>App location: {os.path.abspath(__file__)}</p>
    <p>Database location: {os.path.abspath(DB_FILE)}</p>
    <p>Current directory: {os.getcwd()}</p>
    <p>Python version: {sys.version}</p>
    <p>Server OS: {os.name}</p>
    """
    return info


# 6. XSS (Cross-Site Scripting)
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        # Get the comment from the user.
        comment = request.form.get("comment", "")
        COMMENTS.append(comment)

    # VULNERABLE: The app shows the comment as raw HTML.
    # An attacker can send a JavaScript code inside <script> tags.
    comments_html = "".join([f"<p>{c}</p>" for c in COMMENTS])
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
    # Get the name from the URL.
    name = request.args.get("name", "World")

    # VULNERABLE: The name is put into the template before rendering.
    # An attacker can use {{ }} to run code.
    template = f"<h2>Hello, {name}!</h2>"
    return render_template_string(template)


# 8. CSRF (Cross-Site Request Forgery)
@app.route("/account", methods=["GET", "POST"])
def account():
    if request.method == "POST":
        # Get the new email from the form.
        new_email = request.form.get("email", "")

        # VULNERABLE: The app changes the email without checking if the request is real.
        # It does not use a CSRF token.
        ACCOUNT["email"] = new_email
        return f"<p>Email updated to: {ACCOUNT['email']}</p><a href='/account'>Back</a>"

    # Show the account page.
    return f"""
    <h2>My Account</h2>
    <p>Current email: {ACCOUNT['email']}</p>
    <form method="POST">
        New email: <input type="text" name="email">
        <input type="submit" value="Update email">
    </form>
    <hr>
    <p>Demo attacker page: <a href="/csrf_demo">/csrf_demo</a></p>
    """


@app.route("/csrf_demo")
def csrf_demo():
    # This is a fake attacker page.
    # It will change the user's email automatically.
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