from flask import Flask, abort

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/debug">/debug</a> - Information Disclosure</li>
    </ul>
    """


# 5. INFORMATION DISCLOSURE -> FIXED
@app.route("/debug")
def debug_info():
    # FIXED: the route used to leak the app path, database path, current
    # directory, Python version, and server OS. That kind of internal
    # information should never be exposed, so the route is disabled.
    abort(404)


if __name__ == "__main__":
    app.run(port=5005, debug=False)
