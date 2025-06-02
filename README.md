CyberRecon - Web Reconnaissance & Vulnerability Scanner

CyberRecon is a modular Python-based web reconnaissance and vulnerability scanner designed for ethical hackers, bug bounty hunters, and cybersecurity researchers.

It performs key reconnaissance tasks like DNS lookup, IP geolocation, subdomain enumeration, port scanning, WHOIS lookups, and technology stack detection — all from a single interface.


🔍 Features

- ✅ DNS Record Enumeration (A, AAAA, MX, NS, TXT)
- ✅ Subdomain Enumeration (passive)
- ✅ IP Geolocation & ASN Info
- ✅ Port Scanning (TCP)
- ✅ WHOIS Lookup
- ✅ Tech Stack Detection (Wappalyzer)
- ✅ XSS Injection Testing (via Burp Suite)
- ✅ Burp Suite Proxy Integration (manual testing)
- ✅ Modular design for future vulnerability checks

## 📁 Folder Structure

cyberrecon/
├── config/
│ └── shodan_key.txt
├── modules/
│ ├── dns_info.py
│ ├── ip_info.py
│ ├── ports.py
│ ├── subdomains.py
│ ├── tech_stack.py
│ └── whois_lookup.py
├── main.py
├── README.md
└── requirements.txt

Output Example
[+] Getting DNS Info
[+] Getting IP Info
[+] Enumerating Subdomains
[+] Scanning Open Ports
[+] Running WHOIS Lookup
[+] Detecting Tech Stack

📌 Roadmap
 Auto-scan for reflected XSS

 Basic SQLi test integration

 Local dashboard with Streamlit/Flask

 PDF report generation

 Authentication-aware scans

 🛡️ Disclaimer
CyberRecon is built for ethical hacking and research purposes only.

Use only on targets you own or have written permission to test. Unauthorized usage is illegal.

📘 License
This project is licensed under the MIT License.