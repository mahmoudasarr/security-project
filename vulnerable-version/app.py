"""
Path Traversal Vulnerability - Member 2 (Path Traversal / OS Command Injection / SSRF)
========================================================================================
This file is a standalone test version of the Path Traversal route.
Once finished, this logic gets merged into the main vulnerable-version/app.py

Run with: python app.py
Then visit: http://localhost:5000
"""

from flask import Flask, request
import os

app = Flask(__name__)


@app.route('/')
def home():
    return """
    <h2>Path Traversal - Test Route</h2>
    <a href="/read?file=app.py">Try normal usage</a>
    """


# ==================================================
# PATH TRAVERSAL VULNERABILITY
# ==================================================
# Feature idea: "view a file" feature (e.g. viewing a document or log file)
@app.route('/read')
def read_file():
    # Step 1: Get the file name from the user's input.
    # Default to 'app.py' (this very file) just to have something to show.
    file_name = request.args.get('file', 'app.py')

    # Step 2: Get the folder where THIS script lives on disk.
    # NOTE: while testing standalone here, base_dir points to
    # routes/member1-Mahmoud/ — so exploiting it needs MORE "../" than
    # it will once merged into the main app.py at the project root.
    # That's expected and fine; it changes depending on how deep the
    # running file is nested, not on the vulnerability itself.
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Step 3: VULNERABLE — we blindly join the base folder with whatever
    # the user typed, without checking if it tries to "escape" the folder.
    #
    # Example attack (adjust the number of ../ based on how deep this
    # file currently sits):
    #   /read?file=../../../../../../etc/passwd
    target_path = os.path.join(base_dir, file_name)

    # Step 4: Try to open and return the file content.
    try:
        with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        # Showing the raw error is ALSO a small "Information Disclosure"
        # issue — it reveals internal file paths.
        return f"Error: {str(e)}"


if __name__ == '__main__':
    app.run(port=5000, debug=True)