Vulnerability Scanner (Mini Project)

A compact Python script that scans a host for open ports, risky configurations and outdated software, then generates a simple vulnerability report.

Built as Task 2 of the Thiranex internship. Uses only the Python standard library, so there is nothing to install.

Disclaimer: For educational use only. Scan only systems you own or have explicit written permission to test. Safe practice targets are 127.0.0.1 and scanme.nmap.org.

Features
Open ports and weak configurations: multi-threaded TCP scan; flags risky exposed services (Telnet, SMB, RDP, Redis, MongoDB and others) and missing HTTP security headers.
Outdated software detection: grabs service banners and compares detected versions against a minimum-version table.
Vulnerability report: prints findings sorted by severity (Critical, High, Medium, Low) and saves them to report.txt.
Requirements
Python 3.7 or newer
Usage
bash
python vuln_mini.py <target> [ports]

# Scan default common ports on your own machine
python vuln_mini.py 127.0.0.1

# Scan specific ports
python vuln_mini.py 127.0.0.1 22,80,8080

To get results while testing locally, start a test web server in another terminal (python -m http.server 8080) and scan port 8080.

Sample output
VULNERABILITY REPORT - 127.0.0.1 - 2026-10-08 13:48
Open ports: 8080

1. [LOW] Missing header: content-security-policy (port 8080)
   Fix: Add this security header.
2. [LOW] Missing header: x-frame-options (port 8080)
   Fix: Add this security header.



How it works
Port scan: opens a TCP connection to each port using a thread pool.
Banner grabbing: reads the service greeting (or sends an HTTP HEAD request) to identify software and versions.
Analysis: matches results against tables of risky services, minimum safe versions and expected security headers.
Report: sorts findings by severity and writes report.txt.
Limitations
Version detection relies on banners, which can be hidden or spoofed.
The minimum-version table is illustrative; verify against vendor advisories and CVE databases.
It only detects and reports. It does not exploit anything.
Possible improvements
CVE lookup using the NVD API
HTML or JSON report output
UDP scanning and SSL/TLS certificate checks# Thiranex_task-2
