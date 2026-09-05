import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/read?file=app1_path_traversal.py">/read</a> - Path Traversal</li>
    </ul>
    """


# 1. PATH TRAVERSAL -> FIXED
@app.route("/read")
def read_file():
    default_file = os.path.basename(__file__)
    filename = request.args.get("file", default_file)

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # FIXED: reject any absolute path or ".." traversal attempt, then
    # confirm the final resolved path is still inside base_dir.
    if filename.startswith("/") or ".." in filename:
        return "Invalid filename", 400

    file_path = os.path.realpath(os.path.join(base_dir, filename))
    if not file_path.startswith(base_dir + os.sep):
        return "Invalid filename", 400

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()

        return f"<h2>File Content</h2><pre>{content}</pre>"

    except Exception as e:
        return f"Error reading file: {str(e)}", 400


if __name__ == "__main__":
    app.run(port=5001, debug=False)
