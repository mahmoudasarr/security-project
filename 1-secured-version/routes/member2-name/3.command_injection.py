from flask import Flask, request
import subprocess
import ipaddress

app = Flask(__name__)


@app.route("/ping")
def ping():
    ip_text = request.args.get(
        "ip",
        "127.0.0.1"
    )

    # Accept only a valid IPv4/IPv6 address
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return "Invalid IP address", 400

    try:
        result = subprocess.run(
            [
                "ping",
                "-c",
                "1",
                str(ip)
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )

    except (
        OSError,
        subprocess.TimeoutExpired
    ) as exc:
        return f"Ping failed: {exc}", 502

    output = result.stdout + result.stderr

    return f"<pre>{output}</pre>"


if __name__ == "__main__":
    app.run(debug=False)