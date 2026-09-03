# Web Application Security — Final Project

## Project Overview

This project is part of the Web Application Security Track. It demonstrates
practical understanding of common web vulnerabilities by building the same
web application in two versions:

1. **Vulnerable Version** — intentionally contains real security
   vulnerabilities for educational purposes.
2. **Secured Version** — same application and features, but with every
   vulnerability properly fixed.

The goal is to show how each vulnerability works, how it can be exploited,
and how it can be correctly prevented.

## Vulnerabilities Covered

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF)
- OS Command Injection
- Server-Side Template Injection (SSTI)
- Path Traversal
- Information Disclosure

Each vulnerability appears in the vulnerable version and is properly fixed
in the secured version.

## Tech Stack

- Backend: PHP
- Database: MySQL

## Team Rules

- This is a **team project**, not an individual one. Team members were
  assigned by the organizer and cannot be changed or swapped.
- Every member must contribute and have a clearly assigned responsibility.
- Every member must be able to explain the part they worked on during
  the final discussion.
- Any member can be asked general questions about the whole project, not
  only their own part — everyone needs a working understanding of the
  full app.
- The final result must feel like **one integrated project**, not separate
  pieces stitched together with no shared understanding.

## Vulnerable Version Requirements

- Include working, demonstrable examples of every vulnerability listed
  above.
- Keep the application functionality simple — the goal is to show the
  security issue clearly, not to build a full commercial product.
- Connect each vulnerability to a realistic feature (login, search,
  comments, profile, file download, etc.) whenever possible.

## Secured Version Requirements

- Same core functionality and features as the vulnerable version.
- Every vulnerability from the vulnerable version must be properly fixed
  using the correct prevention technique.
- The team must understand *why* the vulnerability existed, not just
  how it was patched.

## GitHub Requirements

- The full project must be uploaded to GitHub, either as:
  - One repo with two folders (`vulnerable-version/`, `secured-version/`), or
  - Two separate repos (`project-vulnerable`, `project-secured`)
- Each repo/folder needs its own `README.md` covering: project overview,
  team members, responsibilities, how to run it, vulnerabilities
  implemented, and fixes applied.
- Use **meaningful, incremental commits** — avoid uploading the whole
  project in a single final commit.

## Submission Requirements

- One submission per team, through the official Submission Form.
- One ZIP file named like: `Team_XX_ProjectName.zip`
- Must include: source code, presentation, README, results/outputs,
  run screenshots, a short demo video, and any supporting files.
- **Deadline: Monday, September 7, 2026**

## Before Submitting — Checklist

- [ ] Code runs from start to finish with no errors
- [ ] Nothing depends on files or variables that only exist on one
      member's machine
- [ ] Any required libraries/packages are listed in the README or a
      requirements file
- [ ] Presentation, video, screenshots, and code all match the same
      final version of the project
- [ ] ZIP file is named correctly

## Project Discussion

- Each team gets 15–20 minutes.
- Expected flow: **Project Idea → Approach → Implementation → Results →
  Final Output**
- No need to explain every line of code — the focus is on understanding
  decisions made and results achieved.
- Any team member can be questioned about any part of the project.

## Presentation Guidelines

- Keep it short and direct — avoid large blocks of text on slides.
- Focus on: **Problem → Workflow → Implementation → Key Visuals/Outputs →
  Results → Conclusion**

## Important Security Note

The vulnerable version is for **educational and testing purposes only**.
It must never be deployed publicly with real users or sensitive data.
Use only dummy data, test accounts, and local/controlled environments.

## Status

Project in progress. Deadline: Monday, September 7, 2026.