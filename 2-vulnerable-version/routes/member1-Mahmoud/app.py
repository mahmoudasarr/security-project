from flask import Flask, request
import os
import urllib.request
import sys
import sqlite3

app = Flask(__name__)

DB_FILE = "users.db"


# Creates the database and a test user, only if it doesn't exist yet.
def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
        conn.execute("INSERT INTO users VALUES ('admin', '123456')")
        conn.commit()
        conn.close()


@app.route('/')
def home():
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/read?file=app.py">/read</a> - Path Traversal</li>
        <li><a href="/fetch?url=http://example.com">/fetch</a> - SSRF</li>
        <li><a href="/ping?ip=127.0.0.1">/ping</a> - OS Command Injection</li>
        <li><a href="/login">/login</a> - SQL Injection</li>
        <li><a href="/debug">/debug</a> - Information Disclosure</li>
    </ul>
    """


# 1. PATH TRAVERSAL
@app.route('/read')
def read_file():
    file_name = request.args.get('file', 'app.py')

    # Get folder path of this file, so it works from any folder.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, file_name)

    # VULNERABLE: file_name is used with no check.
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    return f"<pre>{content}</pre>"


# 2. SSRF
@app.route('/fetch')
def fetch_url():
    target_url = request.args.get('url', 'http://example.com')

    # VULNERABLE: server visits any URL with no check.
    response = urllib.request.urlopen(target_url)
    content = response.read().decode('utf-8', errors='ignore')
    return f"<pre>{content}</pre>"


@app.route('/admin')
def admin_panel():
    return "SECRET ADMIN PANEL: Only accessible internally!"


# 3. OS COMMAND INJECTION
@app.route('/ping')
def ping():
    ip = request.args.get('ip', '127.0.0.1')

    # VULNERABLE: user input goes straight into the command.
    command = "ping -c 1 " + ip
    output = os.popen(command).read()
    return f"<pre>{output}</pre>"


# 4. SQL INJECTION
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Show the login form on a normal GET request.
    if request.method == 'GET':
        return """
        <h2>Login</h2>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        """

    # Handle the form submission (POST).
    username = request.form.get('username', '')
    password = request.form.get('password', '')

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
@app.route('/debug')
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


if __name__ == '__main__':
    init_db()
    app.run(port=5000, debug=True)