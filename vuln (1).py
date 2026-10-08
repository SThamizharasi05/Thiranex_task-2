"""Mini Vulnerability Scanner - usage: python vuln_mini.py 127.0.0.1 [ports]
Only scan systems you own or have permission to test."""
import socket, re, sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Risky services: port -> (name, severity, advice)
RISKY = {
    21: ("FTP", "MEDIUM", "Sends passwords in clear text. Use SFTP."),
    23: ("Telnet", "HIGH", "Unencrypted. Replace with SSH."),
    445: ("SMB", "HIGH", "Common exploit target. Restrict access."),
    3306: ("MySQL", "MEDIUM", "Database exposed. Use a firewall."),
    3389: ("RDP", "HIGH", "Brute-force target. Restrict access."),
    5900: ("VNC", "HIGH", "Often weak authentication."),
    6379: ("Redis", "HIGH", "Often no authentication."),
    27017: ("MongoDB", "HIGH", "Often no authentication."),
}
COMMON = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 6379, 8080, 27017]

# Minimum recommended versions (illustrative - verify with vendor advisories)
MIN_VER = {"openssh": (9, 0), "apache": (2, 4, 58), "nginx": (1, 24), "vsftpd": (3, 0, 3), "php": (8, 1)}
HEADERS = ["content-security-policy", "x-frame-options", "x-content-type-options"]


def scan(host, port):
    """Return banner text if the port is open, else None."""
    try:
        with socket.create_connection((host, port), timeout=1) as s:
            s.settimeout(1)
            if port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            try:
                return s.recv(1024).decode(errors="ignore")
            except OSError:
                return ""
    except OSError:
        return None


def analyze(port, banner):
    found = []
    if port in RISKY:
        name, sev, tip = RISKY[port]
        found.append((sev, port, f"Risky service exposed: {name}", tip))
    for prod, minimum in MIN_VER.items():  # outdated software check
        m = re.search(prod + r"[ _/-]?(\d+(?:\.\d+)+)", banner, re.I)
        if m and tuple(map(int, m.group(1).split("."))) < minimum:
            found.append(("HIGH", port, f"Outdated {prod} {m.group(1)}", "Upgrade to a patched version."))
    if banner.startswith("HTTP/"):  # weak HTTP configuration check
        for h in HEADERS:
            if h not in banner.lower():
                found.append(("LOW", port, f"Missing header: {h}", "Add this security header."))
    return found


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python vuln_mini.py <target> [ports e.g. 22,80,443]")
    host = socket.gethostbyname(sys.argv[1])
    ports = [int(p) for p in sys.argv[2].split(",")] if len(sys.argv) > 2 else COMMON
    print(f"[*] Scanning {host} ...")
    with ThreadPoolExecutor(50) as ex:
        banners = list(ex.map(lambda p: scan(host, p), ports))

    open_ports = [(p, b) for p, b in zip(ports, banners) if b is not None]
    findings = [f for p, b in open_ports for f in analyze(p, b)]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: order[f[0]])

    report = [f"VULNERABILITY REPORT - {sys.argv[1]} - {datetime.now():%Y-%m-%d %H:%M}",
              "Open ports: " + (", ".join(str(p) for p, _ in open_ports) or "none"), ""]
    for i, (sev, port, title, tip) in enumerate(findings, 1):
        report.append(f"{i}. [{sev}] {title} (port {port})\n   Fix: {tip}")
    if not findings:
        report.append("No issues detected.")
    text = "\n".join(report)
    print(text)
    open("report.txt", "w").write(text)
    print("\n[+] Saved to report.txt")


main()