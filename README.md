# yohoamn! CyberSuite

A Python and Flask-based cybersecurity toolkit that brings honeypot
monitoring and digital forensics together in one platform.

## Features

### HoneyTrap --- Honeypot & Intrusion Detection

-   Detects common attacks, including SQL Injection, XSS and brute-force
    attempts.
-   Records suspicious login activity.
-   Monitors and blocks suspicious IP addresses.
-   Provides an attack monitoring dashboard.

### StegoVault --- Digital Forensics

-   Hide and extract messages from images using LSB steganography.
-   Inspect and remove image metadata (EXIF).
-   Generate and verify SHA-256 hashes.
-   Maintain a record of forensic activities.

## Technology Stack

-   Python and Flask
-   SQLite
-   HTML, CSS and JavaScript
-   Pillow
-   Werkzeug

## Installation

**1. Clone the repository**

``` bash
git clone https://github.com/yohoamn/yohoamn-cybersuite.git
cd yohoamn-cybersuite
```

**2. Install dependencies**

``` bash
pip install -r requirements.txt
```

**3. Configure the Flask secret key**

Generate a secure key:

``` bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Set the generated value as the `SECRET_KEY` environment variable.

**4. Run the application**

``` bash
py app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Security Notice

CyberSuite is currently a learning and demonstration project and is not
yet production-ready.

Before public deployment, ensure secure authentication, disable debug
mode, protect application secrets and review the application's security
controls.

Use the testing features only on systems you own or have explicit
permission to assess.

## Project Information

**Project:** yohoamn! CyberSuite\
**Developer:** yohoamn!\
**Focus:** Cybersecurity and Digital Forensics

**Repository:** https://github.com/yohoamn/yohoamn-cybersuite

*Built for learning, experimentation and practical cybersecurity
exploration.*
