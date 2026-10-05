# ================================================
# Network IDS - Alert Engine
# Author: Ansh
# Phase 4 - Rule Based Detection
# ================================================

from collections import defaultdict
from datetime import datetime
import time
import json
import os

# ── Session-Based Logging ─────────────────────────
SESSION_DIR = os.environ.get(
    'SESSION_LOG_DIR', 'logs'
)
os.makedirs(SESSION_DIR, exist_ok=True)
ALERT_LOG = os.path.join(SESSION_DIR, "alerts.json")

# ── Alert Cooldown (prevent spam) ───────────────
last_alert = {}
COOLDOWN   = 10  # seconds between same alert type

def should_alert(alert_type, src_ip):
    key = f"{alert_type}_{src_ip}"
    now = time.time()
    if key not in last_alert or \
       now - last_alert[key] > COOLDOWN:
        last_alert[key] = now
        return True
    return False
# ── Tracking Dictionaries ────────────────────────
port_tracker    = defaultdict(set)
request_tracker = defaultdict(list)
icmp_tracker    = defaultdict(list)
ssh_tracker     = defaultdict(list)

# ── Blacklisted IPs ──────────────────────────────
BLACKLIST = {
    "10.0.0.99",
    "192.168.1.200",
}

# ── Suspicious Ports ─────────────────────────────
SUSPICIOUS_PORTS = {
    4444 : "Metasploit Reverse Shell",
    1337 : "Common Backdoor Port",
    31337: "Elite/Backdoor Port",
    9001 : "Tor Port",
    6667 : "IRC (Botnet C2)",
}

# ── Alert Severity ───────────────────────────────
SEVERITY = {
    "PORT_SCAN"      : "🟠 HIGH",
    "DOS_ATTACK"     : "🔴 CRITICAL",
    "BLACKLIST_IP"   : "🔴 CRITICAL",
    "SSH_BRUTE"      : "🟠 HIGH",
    "REVERSE_SHELL"  : "🔴 CRITICAL",
    "ICMP_SWEEP"     : "🟡 LOW",
    "SUSPICIOUS_PORT": "🟠 HIGH",
    "UDP_FLOOD"      : "🔴 CRITICAL",
}

# ── Fire Alert ───────────────────────────────────
def fire_alert(alert_type, src_ip, dst_ip, detail=""):
    # Check cooldown first
    if not should_alert(alert_type, src_ip):
        return None
    severity  = SEVERITY.get(alert_type, "🟡 MEDIUM")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = {
        "timestamp"  : timestamp,
        "type"       : alert_type,
        "severity"   : severity,
        "src_ip"     : src_ip,
        "dst_ip"     : dst_ip,
        "detail"     : detail
    }

    # Print to terminal
    print(f"\n{'='*55}")
    print(f"🚨 ALERT FIRED!")
    print(f"   Time     : {timestamp}")
    print(f"   Type     : {alert_type}")
    print(f"   Severity : {severity}")
    print(f"   Source   : {src_ip}")
    print(f"   Target   : {dst_ip}")
    print(f"   Detail   : {detail}")
    print(f"{'='*55}\n")

    # Save to JSON log
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")

    return alert

# ── Rule 1: Blacklist Check ──────────────────────
def check_blacklist(src_ip, dst_ip):
    if src_ip in BLACKLIST:
        fire_alert("BLACKLIST_IP", src_ip, dst_ip,
                   "Packet from known malicious IP")
        return True
    return False

# ── Rule 2: Port Scan Detection ──────────────────
def check_port_scan(src_ip, dst_ip, dst_port,
                    threshold=15):
    if dst_port:
        port_tracker[src_ip].add(dst_port)
        count = len(port_tracker[src_ip])
        if count == threshold:
            fire_alert("PORT_SCAN", src_ip, dst_ip,
                       f"Scanned {count} unique ports")

# ── Rule 3: DoS Detection ────────────────────────
def check_dos(src_ip, dst_ip,
              threshold=100, window=5):
    now = time.time()
    request_tracker[src_ip].append(now)
    # Keep only recent requests within window
    request_tracker[src_ip] = [
        t for t in request_tracker[src_ip]
        if now - t < window
    ]
    count = len(request_tracker[src_ip])
    if count >= threshold:
        fire_alert("DOS_ATTACK", src_ip, dst_ip,
                   f"{count} requests in {window}s")

# ── Rule 4: SSH Brute Force ──────────────────────
def check_ssh_brute(src_ip, dst_ip, dst_port,
                    threshold=5, window=60):
    if dst_port == 22:
        now = time.time()
        ssh_tracker[src_ip].append(now)
        ssh_tracker[src_ip] = [
            t for t in ssh_tracker[src_ip]
            if now - t < window
        ]
        count = len(ssh_tracker[src_ip])
        if count >= threshold:
            fire_alert("SSH_BRUTE", src_ip, dst_ip,
                       f"{count} SSH attempts in {window}s")

# ── Rule 5: Reverse Shell Detection ─────────────
def check_reverse_shell(src_ip, dst_ip, dst_port):
    if dst_port in SUSPICIOUS_PORTS:
        detail = SUSPICIOUS_PORTS[dst_port]
        fire_alert("REVERSE_SHELL", src_ip, dst_ip,
                   f"Port {dst_port} - {detail}")

# ── Rule 6: ICMP Sweep ───────────────────────────
def check_icmp_sweep(src_ip, dst_ip,
                     threshold=10, window=5):
    now = time.time()
    icmp_tracker[src_ip].append(now)
    icmp_tracker[src_ip] = [
        t for t in icmp_tracker[src_ip]
        if now - t < window
    ]
    count = len(icmp_tracker[src_ip])
    if count >= threshold:
        fire_alert("ICMP_SWEEP", src_ip, dst_ip,
                   f"{count} ICMP packets in {window}s")

# ── Run All Checks on a Packet ───────────────────
def run_checks(packet_entry):
    src_ip   = packet_entry.get("src_ip")
    dst_ip   = packet_entry.get("dst_ip")
    protocol = packet_entry.get("protocol")
    dst_port = packet_entry.get("dst_port")

    if not src_ip or not dst_ip:
        return

    # Run all detection rules
    check_blacklist(src_ip, dst_ip)

    if protocol == "TCP":
        check_port_scan(src_ip, dst_ip, dst_port)
        check_dos(src_ip, dst_ip)
        check_ssh_brute(src_ip, dst_ip, dst_port)
        check_reverse_shell(src_ip, dst_ip, dst_port)

    elif protocol == "UDP":
        check_dos(src_ip, dst_ip,
                  threshold=500, window=5)

    elif protocol == "ICMP":
        check_icmp_sweep(src_ip, dst_ip)

