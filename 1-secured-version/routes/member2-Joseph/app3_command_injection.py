import ipaddress
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/ping?ip=127.0.0.1">/ping</a> - OS Command Injection</li>
    </ul>
    """


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


if __name__ == "__main__":
    app.run(port=5003, debug=False)
