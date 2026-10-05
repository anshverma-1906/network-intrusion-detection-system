# ================================================
# Network IDS - Web Dashboard
# Author: Ansh
# Phase 6 - Session-Based Flask Dashboard
# ================================================

from flask import Flask, render_template, jsonify
import json, os, glob
from datetime import datetime

app = Flask(__name__)

# ── Base Path ────────────────────────────────────
BASE = os.path.dirname(os.path.dirname(
           os.path.abspath(__file__)))

# ── Current Session Logs ─────────────────────────
def get_current_logs():
    """Always read from current session symlinks"""
    return {
        "packets"  : os.path.join(BASE,
                        "logs/current_packets.json"),
        "alerts"   : os.path.join(BASE,
                        "logs/current_alerts.json"),
        "ml_alerts": os.path.join(BASE,
                        "logs/current_ml_alerts.json")
    }

# ── Session Info ─────────────────────────────────
def get_session_info():
    """Get current session information"""
    sessions_dir = os.path.join(BASE, "logs/sessions")
    if not os.path.exists(sessions_dir):
        return None
    sessions = sorted(
        glob.glob(f"{sessions_dir}/*/session_info.json"),
        reverse=True
    )
    if not sessions:
        return None
    with open(sessions[0]) as f:
        return json.load(f)

# ── Past Sessions ─────────────────────────────────
def get_past_sessions():
    """Get list of all past sessions"""
    sessions_dir = os.path.join(BASE, "logs/sessions")
    if not os.path.exists(sessions_dir):
        return []
    sessions = []
    for info_file in sorted(
        glob.glob(f"{sessions_dir}/*/session_info.json"),
        reverse=True
    )[:10]:  # Last 10 sessions
        try:
            with open(info_file) as f:
                sessions.append(json.load(f))
        except:
            pass
    return sessions

# ── Count Lines ───────────────────────────────────
def count_lines(filepath):
    if not os.path.exists(filepath) or \
       not os.path.isfile(filepath):
        return 0
    try:
        with open(filepath) as f:
            return sum(1 for l in f if l.strip())
    except:
        return 0

# ── Read Last N Lines ─────────────────────────────
def read_last_lines(filepath, n=200):
    entries = []
    if not os.path.exists(filepath) or \
       not os.path.isfile(filepath):
        return entries
    try:
        with open(filepath) as f:
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
    except:
        pass
    return entries

# ── Routes ────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    logs      = get_current_logs()
    session   = get_session_info()

    # Current session counts
    total_packets = count_lines(logs["packets"])
    total_alerts  = count_lines(logs["alerts"])
    total_ml      = count_lines(logs["ml_alerts"])

    # Recent data
    packets   = read_last_lines(logs["packets"],   200)
    alerts    = read_last_lines(logs["alerts"],    500)
    ml_alerts = read_last_lines(logs["ml_alerts"],  50)

    # Protocol breakdown
    proto_count = {
        "TCP":0, "UDP":0, "ICMP":0, "OTHER":0
    }
    for p in packets:
        proto = p.get("protocol", "OTHER")
        proto_count[proto] = \
            proto_count.get(proto, 0) + 1

    # Alert types
    alert_types = {}
    for a in alerts:
        if "type" in a:
            t = a["type"]
            alert_types[t] = \
                alert_types.get(t, 0) + 1

    # Top IPs
    ip_count = {}
    for p in packets:
        ip = p.get("src_ip", "unknown")
        ip_count[ip] = ip_count.get(ip, 0) + 1
    top_ips = sorted(
        ip_count.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    # Session duration
    duration = "N/A"
    if session and "start_time" in session:
        try:
            start = datetime.strptime(
                session["start_time"],
                "%a %b %d %H:%M:%S %Z %Y"
            )
            diff  = datetime.now() - start
            mins  = int(diff.total_seconds() // 60)
            secs  = int(diff.total_seconds() % 60)
            duration = f"{mins}m {secs}s"
        except:
            duration = "Active"

    return jsonify({
        "session"       : session,
        "duration"      : duration,
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

@app.route("/api/sessions")
def sessions():
    return jsonify(get_past_sessions())

if __name__ == "__main__":
    print("🛡️  IDS Dashboard → http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
