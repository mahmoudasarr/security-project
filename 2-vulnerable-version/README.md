# Vulnerable Version - README

## Overview

This is the intentionally vulnerable version of the application. Each
route below contains a real, working vulnerability for educational
purposes only.

**Team 13** — Web Application Security Track

## Tech Stack

- Backend: Python (Flask)
- Database: SQLite (`users.db`, created automatically on first run)

## How to Run

```bash
python app.py
```

Then open: http://localhost:5000

A test user is created automatically:
- Username: `admin`
- Password: `123456`

## Vulnerabilities (8/8)

### 1. Path Traversal — `/read`

**What it does:** Reads and displays the content of a file whose name
comes from the URL.

**Why it's vulnerable:** The file name is joined directly onto the
app's folder path with no check on where it actually points.

**Exploit:**
```
http://localhost:5000/read?file=app.py
http://localhost:5000/read?file=../../../../etc/passwd
```

---

### 2. SSRF (Server-Side Request Forgery) — `/fetch`

**What it does:** Fetches and displays the content of a URL provided
by the user.

**Why it's vulnerable:** The server visits any URL given, with no
check on the domain or whether it points to an internal address.

**Exploit:**
```
http://localhost:5000/fetch?url=http://example.com
http://localhost:5000/fetch?url=http://127.0.0.1:5000/admin
```

---

### 3. OS Command Injection — `/ping`

**What it does:** Runs a `ping` command using an IP address provided
by the user.

**Why it's vulnerable:** The user's input is joined directly into a
shell command string, so extra commands can be chained after it.

**Exploit:**
```
http://localhost:5000/ping?ip=127.0.0.1
http://localhost:5000/ping?ip=127.0.0.1; whoami
```

---

### 4. SQL Injection — `/login`

**What it does:** Logs a user in by checking their credentials
against the database.

**Why it's vulnerable:** The username and password are inserted
directly into the SQL query string.

**Exploit:** In the username field on the `/login` page, enter:
```
admin' -- 
```
with any password. Login succeeds with no correct password needed.

---

### 5. Information Disclosure — `/debug`

**What it does:** Displays internal server information.

**Why it's vulnerable:** File paths, working directory, Python
version, and OS details are exposed to any visitor.

**Exploit:**
```
http://localhost:5000/debug
```
In a real attack, this path would typically be discovered through
**fuzzing** (e.g. with `ffuf` or `dirsearch`), not guessed directly.

---

### 6. XSS (Cross-Site Scripting) — `/comments`

**What it does:** A comment box where submitted comments are shown to
every visitor.

**Why it's vulnerable:** Comments are inserted into the page with no
escaping.

**Exploit:** Post this as a comment:
```html
<script>alert('XSS')</script>
```
A popup appears, proving the script executed.

---

### 7. SSTI (Server-Side Template Injection) — `/greet`

**What it does:** Greets the user using a name from the URL.

**Why it's vulnerable:** The input is inserted into the template
string before it's rendered, so Jinja2 treats it as template code.

**Exploit:**
```
http://localhost:5000/greet?name={{7*7}}
```
If the page shows `Hello, 49!`, the expression was executed on the
server.

---

### 8. CSRF (Cross-Site Request Forgery) — `/account`

**What it does:** Lets a user update their account email.

**Why it's vulnerable:** The email is changed on any POST request
with no CSRF token to verify it came from our own form.

**Exploit:**
1. Open `http://localhost:5000/account` — note the current email.
2. Open `http://localhost:5000/csrf_demo` in another tab — a hidden
   form there auto-submits to `/account`.
3. Go back to `/account` — the email is now `attacker@evil.com`,
   with no click or confirmation from the user.

---

## Summary Table

| # | Vulnerability | Route |
|---|---|---|
| 1 | Path Traversal | `/read` |
| 2 | SSRF | `/fetch` |
| 3 | OS Command Injection | `/ping` |
| 4 | SQL Injection | `/login` |
| 5 | Information Disclosure | `/debug` |
| 6 | XSS | `/comments` |
| 7 | SSTI | `/greet` |
| 8 | CSRF | `/account` |

## Important Note

This version is for **educational and testing purposes only**. Never
deploy it publicly with real data. Use only local/controlled
environments with dummy data.