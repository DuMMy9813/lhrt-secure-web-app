---

## Overview

This project analyses Ur/Web as a framework that supports secure web application 
development by design. The same application — a personal health record tracker — 
is built twice:

1. **PHP version** — a fully functional but deliberately vulnerable web application 
   exposing real OWASP Top-10 weaknesses
2. **Ur/Web version** — a functionally equivalent application where the same 
   vulnerabilities are structurally impossible due to Ur/Web's type system

---

## Vulnerabilities Demonstrated (PHP)

| Vulnerability | Description |
|---|---|
| SQL Injection | User input concatenated directly into SQL queries |
| XSS | Session cookies stolen via injected JavaScript |
| CSRF | No token validation on form submissions |
| IDOR | Any user can view or delete any other user's records |
| Weak Hashing | Passwords stored using MD5 with no salt |
| Session Fixation | Session ID never regenerated after login |

---

## Security Guarantees (Ur/Web)

Ur/Web eliminates these vulnerabilities at the **compiler level**:

- **SQL Injection** — impossible: typed `{[param]}` antiquotation enforces 
  separation between data and instructions
- **XSS** — impossible: `{[…]}` combinator auto-escapes all HTML output
- **CSRF** — impossible: runtime injects synchroniser tokens automatically
- **IDOR** — prevented: ownership enforced in every query via `AND UserId = {[uid]}`
- **Weak Hashing** — prevented: bcrypt via `Crypto.bcryptCheck`
- **Session Fixation** — prevented: cryptographic session IDs, auto-regenerated

---

## PHP Application Setup

### Requirements
- XAMPP (Apache + MySQL)

### Steps
1. Copy `vulnerable-php-app/` files to `C:\xampp\htdocs\health-tracker\`
2. Open phpMyAdmin at `localhost/phpmyadmin`
3. Create database `health_tracker`
4. Import `database.sql`
5. Visit `localhost/health-tracker`

### Test Credentials
- Username: `bishal` / Password: `password123`
- Username: `anju` / Password: `password123`

---

## Ur/Web Application Setup

### Requirements
- Ur/Web compiler (http://www.impredicative.com/ur/)
- SQLite3

### Steps
```bash
cd secure-urweb-app
urweb healthtracker
./healthtracker.exe -p 8080
```

Visit `http://localhost:8080/Healthtracker/main`

---

## Automated Translator

The Python translator scans PHP source code, detects vulnerabilities, and 
generates secure Ur/Web equivalents automatically.

```bash
cd php-to-urweb-translator
python translator.py --input ../vulnerable-php-app/ --output ../translation-output/ --verbose
```

### Results
- **4 files** scanned
- **8 vulnerabilities** detected and remediated
- **< 1 second** execution time

---

## References

- Ur/Web: http://www.impredicative.com/ur/
- OWASP Top Ten: https://owasp.org/www-project-top-ten/
- A. Chlipala, "Ur/Web: A Simple Model for Programming the Web," POPL 2015
