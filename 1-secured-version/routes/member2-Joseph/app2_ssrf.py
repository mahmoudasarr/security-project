import socket
import ipaddress
import urllib.request
from urllib.parse import urlparse
from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/fetch?url=http://example.com">/fetch</a> - SSRF</li>
    </ul>
    """


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


if __name__ == "__main__":
    app.run(port=5002, debug=False)
