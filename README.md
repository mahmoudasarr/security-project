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

## Project Structure

```
security-project/
├── README.md                  (this file)
├── 2-vulnerable-version/
│   └── app.py
└── 1-secured-version/
    └── app.py
```

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

Both versions are complete — all 8 vulnerabilities are implemented in
the vulnerable version and properly fixed in the secured version.

## Team Members and Responsibilities

### Mahmoud Asar — Project Lead

- Built the entire vulnerable version of the application (all 8
  vulnerabilities: Path Traversal, SSRF, OS Command Injection, SQL
  Injection, Information Disclosure, XSS, SSTI, CSRF).
- Created and organized the GitHub repository for both versions.
- Set up the project's file structure, including per-member folders
  for the team to work in.
- Supervised the overall project and coordinated the team's work.
- Reviewed and fixed bugs in the secured version — specifically
  vulnerabilities #1 (Path Traversal) and #2 (SSRF).
- Tested both the vulnerable and secured applications end-to-end to
  confirm they work correctly.
- Took and organized all run screenshots.
- Recorded and edited the project demo video for both versions.
- Organized and prepared the final submission attachments.

### Joseph

- Fixed vulnerability #1 (Path Traversal) in the secured version.
- Fixed vulnerability #5 (Information Disclosure) in the secured
  version.
- Fixed vulnerability #6 (XSS) in the secured version.
- Fixed vulnerability #7 (SSTI) in the secured version.
- Fixed vulnerability #8 (CSRF) in the secured version.
- Split the fixes across multiple organized files.
- Wrote documentation explaining how both versions work.
- Assisted with several other parts of the project.

### Mohamed Ali

- Fixed vulnerability #2 (SSRF) in the secured version.
- Fixed vulnerability #3 (OS Command Injection) in the secured
  version.
- Fixed vulnerability #4 (SQL Injection) in the secured version.

### Abdelrahman Ahmed

- Fixed vulnerability #7 (SSTI) in the secured version.
- Fixed vulnerability #8 (SSRF) in the secured version.
- Fixed Timming attack in SSRF.

### Contribution Summary

| #   | Vulnerability          | Vulnerable Version | Secured Version (Fix)      |
| --- | ---------------------- | ------------------ | -------------------------- |
| 1   | Path Traversal         | Mahmoud Asar       | Mahmoud Asar / Joseph      |
| 2   | SSRF                   | Mahmoud Asar       | Mahmoud Asar / Mohamed Ali |
| 3   | OS Command Injection   | Mahmoud Asar       | Mohamed Ali                |
| 4   | SQL Injection          | Mahmoud Asar       | Mohamed Ali                |
| 5   | Information Disclosure | Mahmoud Asar       | Joseph                     |
| 6   | XSS                    | Mahmoud Asar       | Joseph                     |
| 7   | SSTI                   | Mahmoud Asar       | Abelrahman                     |
| 8   | CSRF                   | Mahmoud Asar       | Abelrahman                     |

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
cd 2-vulnerable-version
python app.py
```

Runs on http://localhost:5000

**Secured version:**

```bash
cd 1-secured-version
python app.py
```

Runs on http://localhost:5000 (run one version at a time, or change
the port in the secured version's code to run both together)

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
