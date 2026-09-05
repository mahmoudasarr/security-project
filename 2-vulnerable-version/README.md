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

**What it does:** Reads and displays the content of a file. Accepts
either a plain filename or a full absolute path.

**Why it's vulnerable:** The filename comes straight from the user
with no check on where it points. If it starts with `/`, it's used
as-is (an absolute path); otherwise it's joined onto the app's folder
with no validation that it stays inside it.

**Exploit:**

```
http://localhost:5000/read?file=app.py
http://localhost:5000/read?file=/etc/passwd
```

---

### 2. SSRF (Server-Side Request Forgery) — `/fetch` → `/admin`

**What it does:** Fetches and displays the content of a URL provided
by the user.

**Why it's vulnerable:** The server visits any URL given, with no
check on the domain or whether it points to an internal address.

**The `/admin` route in this version has a twist:** it checks the
`User-Agent` header and blocks any request whose User-Agent contains
`Mozilla` or `Chrome` — i.e. it blocks normal browser access directly.
It only responds with the flag when the request does **not** look
like it came from a browser. This is exactly what happens when the
server itself (via `/fetch`, using Python's `urllib`) makes the
request internally — Python's default User-Agent doesn't match those
strings, so the check is bypassed.

**Exploit:**

```
http://localhost:5000/fetch?url=http://127.0.0.1:5000/admin
```

Visiting `/admin` directly in a browser returns `403 Forbidden`.
Reaching it indirectly through `/fetch` succeeds and reveals the flag
— proving the server was tricked into making the request on the
attacker's behalf, bypassing a check that only looks at User-Agent
(not a reliable way to tell internal from external requests).

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
<script>
  alert("XSS");
</script>
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

| #   | Vulnerability          | Route                            |
| --- | ---------------------- | -------------------------------- |
| 1   | Path Traversal         | `/read`                          |
| 2   | SSRF                   | `/fetch` (chained into `/admin`) |
| 3   | OS Command Injection   | `/ping`                          |
| 4   | SQL Injection          | `/login`                         |
| 5   | Information Disclosure | `/debug`                         |
| 6   | XSS                    | `/comments`                      |
| 7   | SSTI                   | `/greet`                         |
| 8   | CSRF                   | `/account`                       |

## Important Note

This version is for **educational and testing purposes only**. Never
deploy it publicly with real data. Use only local/controlled
environments with dummy data.
