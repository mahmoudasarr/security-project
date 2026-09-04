from flask import Flask, request
import os
import urllib.request
import ipaddress
import socket
import shlex
import subprocess
app = Flask(__name__)

@app.route('/')
def home():
    return """
    <h2>Secured App - Demo Routes</h2>
    <ul>
        <li><a href="/read?file=app.py">/read</a> - Path Traversal (fixed)</li>
        <li><a href="/fetch?url=http://example.com">/fetch</a> - SSRF (fixed)</li>
        <li><a href="/ping?ip=127.0.0.1">/ping</a> - OS Command Injection (fixed)</li>
    </ul>
    """

# 1. PATH TRAVERSAL - FIXED
@app.route('/read')
def read_file():
    file_name = request.args.get('file', 'app.py')
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # FIX: build the full path, then resolve it (removes any "..").
    file_path = os.path.abspath(os.path.join(base_dir, file_name))

    # FIX: only allow the file if it's still inside base_dir.
    if not file_path.startswith(base_dir + os.sep):
        return "Error: access denied.", 403

    if not os.path.isfile(file_path):
        return "Error: file not found.", 404

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    return f"<pre>{content}</pre>"

# 2. SSRF - FIXED
@app.route('/fetch')
def fetch_url():
    target_url = request.args.get('url', 'http://example.com')

    # FIX: only allow http/https, and block requests to private/internal
    # IP ranges (localhost, 127.0.0.1, internal networks, etc.).
    try:
        parsed = urllib.request.urlparse(target_url)
        if parsed.scheme not in ('http', 'https'):
            return "Error: only http/https URLs are allowed.", 400

        host = parsed.hostname
        ip = socket.gethostbyname(host)
        if ipaddress.ip_address(ip).is_private:
            return "Error: requests to private addresses are blocked.", 400
    except Exception:
        return "Error: invalid URL.", 400

    response = urllib.request.urlopen(target_url)
    content = response.read().decode('utf-8', errors='ignore')
    return f"<pre>{content}</pre>"


@app.route('/admin')
def admin_panel():
    return "SECRET ADMIN PANEL: Only accessible internally!"

# 3. OS COMMAND INJECTION - FIXED
@app.route('/ping')
def ping():
    ip = request.args.get('ip', '127.0.0.1')

    # FIX: check the input looks like a real IP address before using it.
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "Error: invalid IP address.", 400

    # FIX: pass arguments as a list (no shell), so there is no room
    # for extra shell commands to be injected.
    result = subprocess.run(
        ["ping", "-c", "1", ip],
        capture_output=True, text=True
    )
    return f"<pre>{result.stdout}</pre>"


if __name__ == '__main__':
    app.run(port=5000, debug=True)