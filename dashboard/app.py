# ================================================
# Network IDS - Web Dashboard
# Author: Ansh
# Phase 6 - Flask Dashboard
# ================================================

from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

# ── Log File Paths ───────────────────────────────
BASE      = os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))
PACKETS   = os.path.join(BASE, "logs/packets.json")
ALERTS    = os.path.join(BASE, "logs/alerts.json")
ML_ALERTS = os.path.join(BASE, "logs/ml_alerts.json")

# ── Count Lines in File ──────────────────────────
def count_lines(filepath):
    if not os.path.exists(filepath):
        return 0
    with open(filepath, "r") as f:
        return sum(1 for line in f if line.strip())

# ── Read Last N Lines ────────────────────────────
def read_last_lines(filepath, n=200):
    entries = []
    if not os.path.exists(filepath):
        return entries
    with open(filepath, "r") as f:
        lines = f.readlines()
    for line in lines[-n:]:
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("{"):
                entries.append(json.loads(line))
            else:
                entries.append({"raw": line})
        except:
            pass
    return entries

# ── Routes ───────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    # Real totals from line counts
    total_packets = count_lines(PACKETS)
    total_alerts  = count_lines(ALERTS)
    total_ml      = count_lines(ML_ALERTS)

    # Recent entries for analysis
    packets   = read_last_lines(PACKETS,   200)
    alerts    = read_last_lines(ALERTS,    500)
    ml_alerts = read_last_lines(ML_ALERTS,  50)

    # Protocol breakdown
    proto_count = {"TCP":0,"UDP":0,"ICMP":0,"OTHER":0}
    for p in packets:
        proto = p.get("protocol", "OTHER")
        if proto in proto_count:
            proto_count[proto] += 1
        else:
            proto_count["OTHER"] += 1

    # Alert type breakdown
    alert_types = {}
    for a in alerts:
        if "type" in a:
            t = a["type"]
            alert_types[t] = alert_types.get(t, 0) + 1

    # Top source IPs
    ip_count = {}
    for p in packets:
        ip = p.get("src_ip", "unknown")
        ip_count[ip] = ip_count.get(ip, 0) + 1
    top_ips = sorted(ip_count.items(),
                     key=lambda x: x[1],
                     reverse=True)[:5]

    return jsonify({
        "total_packets" : total_packets,
        "total_alerts"  : total_alerts,
        "total_ml"      : total_ml,
        "protocols"     : proto_count,
        "alert_types"   : alert_types,
        "top_ips"       : top_ips,
        "recent_alerts" : [
            a for a in alerts[-10:][::-1]
            if "type" in a
        ],
        "recent_ml"     : ml_alerts[-5:][::-1],
    })

if __name__ == "__main__":
    print("🛡️  IDS Dashboard → http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
