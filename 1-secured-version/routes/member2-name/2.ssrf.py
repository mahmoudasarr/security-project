from flask import Flask, request
import urllib.request
import urllib.error
import socket
import ipaddress
from urllib.parse import urlparse

app = Flask(__name__)


def is_private_or_local(hostname):
    try:
        addresses = {
            info[4][0]
            for info in socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM
            )
        }
    except socket.gaierror:
        return True

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return True

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        ):
            return True

    return False


@app.route("/fetch")
def fetch_url():
    target_url = request.args.get(
        "url",
        "http://example.com"
    )

    parsed = urlparse(target_url)

    # Only HTTP and HTTPS
    if parsed.scheme not in {"http", "https"}:
        return "Invalid URL", 400

    # Hostname is required
    if not parsed.hostname:
        return "Invalid URL", 400

    # Reject credentials in URL
    if parsed.username or parsed.password:
        return "Invalid URL", 400

    # Allow only standard HTTP/HTTPS ports
    if parsed.port not in (None, 80, 443):
        return "Port not allowed", 403

    # Reject local/private destinations
    if is_private_or_local(parsed.hostname):
        return "Forbidden destination", 403

    request_obj = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": "SecureDemoFetcher/1.0"
        }
    )

    try:
        response = urllib.request.urlopen(
            request_obj,
            timeout=5
        )

        content = response.read(
            1024 * 1024
        ).decode(
            "utf-8",
            errors="ignore"
        )

    except (
        urllib.error.URLError,
        TimeoutError,
        ValueError
    ) as exc:
        return f"Fetch failed: {exc}", 502

    return f"<pre>{content}</pre>"


if __name__ == "__main__":
    app.run(debug=False)