from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/read")
def read_file():
    file_name = request.args.get("file", "app.py")

    # Application directory
    base_dir = os.path.realpath(
        os.path.dirname(os.path.abspath(__file__))
    )

    # Resolve the requested path
    requested_path = os.path.realpath(
        os.path.join(base_dir, file_name)
    )

    # Make sure the requested file stays inside base_dir
    try:
        inside_base = (
            os.path.commonpath([base_dir, requested_path])
            == base_dir
        )
    except ValueError:
        inside_base = False

    if not inside_base:
        return "Forbidden", 403

    if not os.path.isfile(requested_path):
        return "File not found", 404

    with open(
        requested_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:
        content = f.read()

    return f"<pre>{content}</pre>"


if __name__ == "__main__":
    app.run(debug=False)