import secrets
from flask import Flask, request, session, abort

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

ACCOUNT = {"email": "victim@example.com"}


@app.route("/")
def home():
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/account">/account</a> - CSRF</li>
    </ul>
    """


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


# 8. CSRF (Cross-Site Request Forgery) -> FIXED
@app.route("/account", methods=["GET", "POST"])
def account():
    if request.method == "POST":
        # FIXED: require a CSRF token tied to the user's own session.
        # A forged request from another site (like /csrf_demo) cannot
        # know this token, so the request is rejected.
        submitted_token = request.form.get("csrf_token", "")
        if not submitted_token or submitted_token != session.get("csrf_token"):
            abort(403, description="Invalid CSRF token")

        # Get the new email from the form.
        new_email = request.form.get("email", "")
        ACCOUNT["email"] = new_email
        return f"<p>Email updated to: {ACCOUNT['email']}</p><a href='/account'>Back</a>"

    # Show the account page.
    token = get_csrf_token()
    return f"""
    <h2>My Account</h2>
    <p>Current email: {ACCOUNT['email']}</p>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{token}">
        New email: <input type="text" name="email">
        <input type="submit" value="Update email">
    </form>
    <hr>
    <p>Demo attacker page: <a href="/csrf_demo">/csrf_demo</a></p>
    """


@app.route("/csrf_demo")
def csrf_demo():
    # This is a fake attacker page. It tries to change the user's email
    # automatically, but it has no way to know the real csrf_token, so
    # /account will now reject this forged request with 403.
    return """
    <h3>Totally Harmless Page</h3>
    <p>This page tries to silently change your account email.</p>
    <form id="evil" action="/account" method="POST">
        <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>document.getElementById('evil').submit();</script>
    """


if __name__ == "__main__":
    app.run(port=5008, debug=False)
