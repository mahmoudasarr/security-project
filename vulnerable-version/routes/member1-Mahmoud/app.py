from flask import Flask, request
import os
import urllib.request
app = Flask(__name__)

@app.route('/')
def home():
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/read?file=app.py">/read</a> - Path Traversal</li>
        <li><a href="/fetch?url=http://example.com">/fetch</a> - SSRF</li>
        <li><a href="/ping?ip=127.0.0.1">/ping</a> - OS Command Injection</li>
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


if __name__ == '__main__':
    app.run(port=5000, debug=True)