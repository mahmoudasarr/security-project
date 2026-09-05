from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/greet?name=World">/greet</a> - SSTI</li>
    </ul>
    """


# 7. SSTI (Server-Side Template Injection) -> FIXED
@app.route("/greet")
def greet():
    # Get the name from the URL.
    name = request.args.get("name", "World")

    # FIXED: keep the template string fixed/constant and pass "name" in
    # as a Jinja2 variable instead of splicing it into the template text
    # with an f-string. This way user input is only ever treated as data,
    # never as template code, so "{{ }}" payloads can't execute.
    template = "<h2>Hello, {{ name }}!</h2>"
    return render_template_string(template, name=name)


if __name__ == "__main__":
    app.run(port=5007, debug=False)
