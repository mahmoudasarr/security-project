# Secured Version - README

## Overview

This is the secured version of the application. It has the same
features and routes as the vulnerable version, but every
vulnerability has been fixed using the correct prevention technique.

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

## Fixes (8/8)

### 1. Path Traversal — `/read`

**The problem:** The filename came straight from the user with no
check on where it pointed — it could escape the app's folder or be
an absolute path.

**The fix:** The final path is resolved with `os.path.abspath()`
(which removes any `../` tricks), then checked to confirm it's still
located inside the app's own folder. If it isn't, or the file doesn't
exist, the request is rejected. The file content is also passed
through `escape()` before display, so even the file viewer itself
can't be used to inject HTML/JS into the page.

**Result:** `?file=/etc/passwd` and `?file=../../etc/passwd` now
return `403 Access denied`.

---

### 2. SSRF (Server-Side Request Forgery) — `/fetch`

**The problem:** The server would fetch any URL given by the user,
including internal/private addresses like `127.0.0.1`.

**The fix:** Only `http`/`https` URLs are allowed. The target
hostname is resolved to an IP address, and the request is blocked if
that IP is private, loopback, link-local, or otherwise reserved
(covers `127.0.0.1`, `10.x.x.x`, `169.254.x.x`, and similar internal
ranges).

**Result:** `?url=http://127.0.0.1:5000/admin` now returns `Error
fetching URL: internal addresses are blocked` instead of reaching the
internal admin page.

---

### 3. OS Command Injection — `/ping`

**The problem:** User input was inserted directly into a shell
command string, allowing extra commands to be chained with `;` or
`&&`.

**The fix:** The input is first validated as a real IP address using
Python's `ipaddress` module. The command then runs via
`subprocess.run()` with the arguments passed as a list (no shell
involved), so there's no way for special characters to be
interpreted as a second command.

**Result:** `?ip=127.0.0.1; whoami` now returns `Invalid IP address`
before any command runs.

---

### 4. SQL Injection — `/login`

**The problem:** The username and password were inserted directly
into the SQL query string using an f-string.

**The fix:** A parameterized query with `?` placeholders is used
instead. The database driver fills in the values safely and
separately from the query text, so user input can never change the
query's structure.

**Result:** Entering `admin' -- ` as the username no longer bypasses
the password check — it's simply treated as a literal (non-matching)
username.

---

### 5. Information Disclosure — `/debug`

**The problem:** The route exposed the app's file path, database
path, working directory, Python version, and OS name to any visitor.

**The fix:** The route is disabled entirely (`abort(404)`), so it now
behaves like any page that doesn't exist.

**Result:** Visiting `/debug` returns a standard `404 Not Found`.

---

### 6. XSS (Cross-Site Scripting) — `/comments`

**The problem:** Comments were inserted into the page as raw HTML
with no escaping, so submitted `<script>` tags would execute.

**The fix:** The page is now rendered with `render_template_string()`
using Jinja2 `{{ }}` placeholders instead of an f-string. Jinja2
automatically escapes values inserted this way, converting `<` and
`>` into safe text instead of real HTML tags.

**Result:** Posting `<script>alert('XSS')</script>` now displays the
literal text on the page instead of running it.

---

### 7. SSTI (Server-Side Template Injection) — `/greet`

**The problem:** The user's input was spliced into the template
string with an f-string before rendering, so Jinja2 treated it as
template code.

**The fix:** The template string is now fixed (`"<h2>Hello, {{ name
}}!</h2>"`), and the user's input is passed in separately as a Jinja2
variable (`name=name`). Jinja2 only fills in the placeholder and
never treats the value itself as more template code to execute.

**Result:** `?name={{7*7}}` now displays `Hello, {{7*7}}!` literally
instead of `Hello, 49!`.

---

### 8. CSRF (Cross-Site Request Forgery) — `/account`

**The problem:** The email could be changed by any POST request, with
no proof it came from the app's own form.

**The fix:** A secret CSRF token is generated per session and
embedded as a hidden field in the real form. Every POST request must
include the matching token, or it's rejected with `403`. A forged
request from another page (like `/csrf_demo`) has no way to know this
session-specific token.

**Result:** Visiting `/csrf_demo` no longer changes the account email
— the forged request is rejected with `403 Invalid CSRF token`.

---

## Summary Table

| #   | Vulnerability          | Fix Applied                                     |
| --- | ---------------------- | ----------------------------------------------- |
| 1   | Path Traversal         | Resolved path + folder containment check        |
| 2   | SSRF                   | Scheme whitelist + private IP blocking          |
| 3   | OS Command Injection   | IP validation + `subprocess` with argument list |
| 4   | SQL Injection          | Parameterized query                             |
| 5   | Information Disclosure | Route disabled (404)                            |
| 6   | XSS                    | Jinja2 auto-escaping                            |
| 7   | SSTI                   | Fixed template + data passed separately         |
| 8   | CSRF                   | Session-based CSRF token                        |
