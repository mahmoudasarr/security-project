# Web Application Security — Final Project

**Team 13** — Web Application Security Track

## Project Overview

This project demonstrates practical understanding of common web
security vulnerabilities by building the same web application in two
versions:

1. **Vulnerable Version** — intentionally contains 8 real, working
   security vulnerabilities, each tied to a realistic feature (login,
   comments, file viewer, account settings, etc.).
2. **Secured Version** — the exact same features and routes, but with
   every vulnerability properly fixed using the correct prevention
   technique.

The goal is to show both sides of web application security: how
attacks actually work, and how to defend against them correctly.

## Tech Stack

- **Backend:** Python (Flask)
- **Database:** SQLite (single-file database, created automatically)

## The 8 Vulnerabilities

| #   | Vulnerability          | Route               | Status |
| --- | ---------------------- | ------------------- | ------ |
| 1   | Path Traversal         | `/read`             | Done   |
| 2   | SSRF                   | `/fetch` → `/admin` | Done   |
| 3   | OS Command Injection   | `/ping`             | Done   |
| 4   | SQL Injection          | `/login`            | Done   |
| 5   | Information Disclosure | `/debug`            | Done   |
| 6   | XSS                    | `/comments`         | Done   |
| 7   | SSTI                   | `/greet`            | Done   |
| 8   | CSRF                   | `/account`          | Done   |

**Vulnerable version:** complete — all 8 vulnerabilities implemented
and verified working.

**Secured version:** in progress — the team is actively applying
fixes for all 8 vulnerabilities.

## How the Two Versions Compare

Both versions share:

- The same routes and URLs
- The same features and page layout
- The same database structure

The **only** difference is how user input is handled right before
it's used — validated, escaped, or kept separate from
commands/queries in the secured version, versus used directly and
blindly in the vulnerable version.

## How to Run

**Vulnerable version:**

```bash
cd vulnerable-version
python app.py
```

Runs on http://localhost:5000

**Secured version:**

```bash
cd secured-version
python app.py
```

See `secured-version/README.md` for the exact port and setup once
complete.

## Security Concept Behind This Project

Every one of the 8 vulnerabilities here comes from the same root
cause: **trusting user input without checking it**. Every fix follows
one of three ideas:

- **Validate** — check the input is the right shape/type before use
- **Escape** — turn dangerous characters into safe text before display
- **Separate code from data** — never build a command or query by
  gluing text together with user input

## Important Security Note

The vulnerable version is for **educational and testing purposes
only**. It must never be deployed publicly with real users or
sensitive data. Use only dummy data, test accounts, and
local/controlled environments.

## Deadline

Monday, September 7, 2026
