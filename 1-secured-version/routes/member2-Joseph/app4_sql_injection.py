import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

DB_FILE = "users.db"


def init_db():
    # Create the database and a test user if it does not exist.
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
        conn.execute("INSERT INTO users VALUES ('admin', '123456')")
        conn.commit()
        conn.close()


@app.route("/")
def home():
    return """
    <h2>Vulnerable App - Demo Routes</h2>
    <ul>
        <li><a href="/login">/login</a> - SQL Injection</li>
    </ul>
    """


# 4. SQL INJECTION -> FIXED
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Show the login page.
        return """
        <h2>Login</h2>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        """

    # Get data from the form.
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # FIXED: use a parameterized query instead of building the SQL string
    # with f-strings, so user input can never break out of the query.
    query = "SELECT * FROM users WHERE username=? AND password=?"

    conn = sqlite3.connect(DB_FILE)
    result = conn.execute(query, (username, password)).fetchall()
    conn.close()

    if result:
        return "Login successful!"
    return "Invalid credentials."


if __name__ == "__main__":
    init_db()
    app.run(port=5004, debug=False)
