from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Creat e a simple SQLite database and a users table
conn = sqlite3.connect('test.db')
conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
conn.execute("INSERT OR IGNORE INTO users VALUES ('admin', '1234')")
conn.commit()

@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ""
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        
        # Vulnerable to SQL Injection merge in query
        query = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        
        db = sqlite3.connect('test.db')
        user = db.cursor().execute(query).fetchone()
        
        msg = "Logged in!" if user else "Failed!"
        
    return render_template_string('''
        <form method="POST">
            Username: <input name="username"><br>
            Password: <input name="password"><br>
            <button>Login</button>
        </form>
        <h3>{{ msg }}</h3>
    ''', msg=msg)

if __name__ == '__main__':
    app.run(port=5000)