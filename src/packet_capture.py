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

import sys
sys.path.append('/home/kali/Desktop/network-ids')
from config import get_config, print_config

# Auto detect network settings
NET_CONFIG = get_config()
print_config(NET_CONFIG)
INTERFACE  = NET_CONFIG["interface"]
# ── Config ──────────────────────────────────────
# ── Session-Based Logging ─────────────────────────
SESSION_DIR = os.environ.get(
    'SESSION_LOG_DIR', 'logs'
)
os.makedirs(SESSION_DIR, exist_ok=True)
LOG_FILE = os.path.join(SESSION_DIR, "packets.json")
print(f"📁 Session log: {LOG_FILE}")

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
def start_capture(interface=None, count=0):
    iface    = interface or INTERFACE
    local_ip = NET_CONFIG["local_ip"]

    # BPF Filter - only capture YOUR device traffic
    # src or dst must be YOUR IP
    bpf_filter = f"host {local_ip}"

    print(f"""
╔══════════════════════════════════════╗
║   Network IDS - Packet Capture       ║
║   Interface : {iface:<22}║
║   Local IP  : {local_ip:<22}║
║   Filter    : {bpf_filter:<22}║
║   Mode      : Host-Based IDS         ║
║   Press Ctrl+C to stop               ║
╚══════════════════════════════════════╝
    """)

    sniff(
        iface=iface,
        prn=analyze_packet,
        store=False,
        count=count,
        filter=bpf_filter    # ← Only YOUR traffic!
    )

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="🛡️ Network IDS - Packet Capture"
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface (default: auto-detect)",
        default=None
    )
    parser.add_argument(
        "-c", "--count",
        help="Packet count (0=infinite)",
        type=int,
        default=0
    )
    args = parser.parse_args()

    start_capture(
        interface=args.interface,
        count=args.count
    )
