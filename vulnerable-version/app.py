from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return "<h1>MiniShop</h1><p>Web Security Project</p>"


if __name__ == "__main__":
    app.run(debug=True)