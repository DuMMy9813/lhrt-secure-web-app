# Lightweight Health Record Tracker (LHRT)
Secure Web Application Development Using Ur/Web

## Project Structure
- vulnerable-php-app — Deliberately insecure PHP baseline
- secure-urweb-app — Secure Ur/Web implementation  
- php-to-urweb-translator — Automated vulnerability translator
- translation-output — Generated Ur/Web code from translator

## PHP Setup
1. Copy files to C:\xampp\htdocs\health-tracker
2. Import database.sql in phpMyAdmin
3. Visit localhost/health-tracker
4. Login: bishal / password123

## Ur/Web Setup
1. Install Ur/Web compiler from impredicative.com/ur
2. Run: urweb healthtracker
3. Run: ./healthtracker.exe -p 8080
4. Visit: localhost:8080/Healthtracker/main

## Automated Translator
python translator.py --input ../vulnerable-php-app/ --output ../translation-output/ --verbose
Results: 4 files scanned, 8 vulnerabilities remediated in under 1 second

## Vulnerabilities Demonstrated
SQL Injection, XSS, CSRF, IDOR, Weak Hashing, Session Fixation

## References
- Ur/Web: http://www.impredicative.com/ur/
- OWASP Top Ten: https://owasp.org/www-project-top-ten/
