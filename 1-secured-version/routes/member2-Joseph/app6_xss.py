from flask import Flask, request, render_template_string

app = Flask(__name__)

COMMENTS = []


@app.route("/")
def home():
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/comments">/comments</a> - XSS</li>
    </ul>
    """


# 6. XSS (Cross-Site Scripting) -> FIXED
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        # Get the comment from the user.
        comment = request.form.get("comment", "")
        COMMENTS.append(comment)

    # FIXED: use render_template_string with Jinja2 {{ }} placeholders
    # instead of an f-string, so Jinja2's autoescaping neutralizes any
    # HTML/JS the user submits instead of rendering it as raw HTML.
    return render_template_string("""
    <h2>Comments</h2>
    <form method="POST">
        <input type="text" name="comment">
        <input type="submit" value="Post">
    </form>
    {% for c in comments %}
    <p>{{ c }}</p>
    {% endfor %}
    """, comments=COMMENTS)


if __name__ == "__main__":
    app.run(port=5006, debug=False)
