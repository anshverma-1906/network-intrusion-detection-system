# ================================================
# Network IDS - Packet Capture Engine
# Author: Ansh
# Phase 3 - Python Packet Capture
# ================================================

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import json
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from alert_engine import run_checks
from anomaly_detector import predict_packet

# ── Config ──────────────────────────────────────
INTERFACE = "eth0"
LOG_FILE  = "logs/packets.json"
os.makedirs("logs", exist_ok=True)

# ── Packet Counter ───────────────────────────────
stats = {
    "total": 0,
    "tcp"  : 0,
    "udp"  : 0,
    "icmp" : 0,
    "other": 0
}

# ── Process Each Packet ──────────────────────────
def analyze_packet(packet):
    if IP not in packet:
        return

    stats["total"] += 1

    entry = {
        "timestamp" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip"    : packet[IP].src,
        "dst_ip"    : packet[IP].dst,
        "protocol"  : "OTHER",
        "src_port"  : None,
        "dst_port"  : None,
        "flags"     : None,
        "length"    : len(packet),
        "ttl"       : packet[IP].ttl
    }

    if TCP in packet:
        entry["protocol"] = "TCP"
        entry["src_port"] = packet[TCP].sport
        entry["dst_port"] = packet[TCP].dport
        entry["flags"]    = str(packet[TCP].flags)
        stats["tcp"]     += 1

    elif UDP in packet:
        entry["protocol"] = "UDP"
        entry["src_port"] = packet[UDP].sport
        entry["dst_port"] = packet[UDP].dport
        stats["udp"]     += 1

    elif ICMP in packet:
        entry["protocol"] = "ICMP"
        stats["icmp"]    += 1

    else:
        stats["other"] += 1

    # ── Print to Terminal ────────────────────────
    print(f"[{entry['timestamp']}] "
          f"{entry['protocol']:<5} | "
          f"{entry['src_ip']:<16} → {entry['dst_ip']:<16} | "
          f"Port: {str(entry['dst_port']):<6} | "
          f"Len: {entry['length']}")

    # ── Save to JSON Log ─────────────────────────
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

    # ── Print Stats Every 100 Packets ───────────
    if stats["total"] % 100 == 0:
        print(f"\n📊 Stats → Total:{stats['total']} "
              f"TCP:{stats['tcp']} "
              f"UDP:{stats['udp']} "
              f"ICMP:{stats['icmp']}\n")
    # Run alert engine on every packet
    run_checks(entry)
    # ── ML Anomaly Detection ─────────────────────
    predict_packet(entry)

# ── Start Capture ────────────────────────────────
def start_capture(interface=INTERFACE, count=0):
    print(f"""
╔══════════════════════════════════════╗
║   Network IDS - Packet Capture       ║
║   Interface : {interface:<22}║
║   Log File  : {LOG_FILE:<22}║
║   Press Ctrl+C to stop               ║
╚══════════════════════════════════════╝
    """)
    sniff(iface=interface,
          prn=analyze_packet,
          store=False,
          count=count)

if __name__ == "__main__":
    start_capture()
