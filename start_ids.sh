#!/bin/bash
# ================================================
# Network IDS - Master Start Script
# Author: Ansh
# ================================================

clear
echo "================================================"
echo "🛡️  NETWORK INTRUSION DETECTION SYSTEM"
echo "================================================"

# ── Create Session ID ────────────────────────────
SESSION_ID=$(date +"%Y%m%d_%H%M%S")
SESSION_DIR="logs/sessions/$SESSION_ID"
mkdir -p $SESSION_DIR

echo ""
echo "📅 Session ID : $SESSION_ID"
echo "📁 Session Dir: $SESSION_DIR"

# ── Auto detect network ──────────────────────────
INTERFACE=$(ip route show default | \
            awk '/default/ {print $5}')
LOCAL_IP=$(hostname -I | awk '{print $1}')
GATEWAY=$(ip route show default | \
          awk '/default/ {print $3}')
SUBNET=$(ip route | grep -v default | \
         grep $INTERFACE | \
         awk '{print $1}' | head -1)

echo ""
echo "🔍 Network Detected:"
echo "   Interface : $INTERFACE"
echo "   Local IP  : $LOCAL_IP"
echo "   Gateway   : $GATEWAY"
echo "   Subnet    : $SUBNET"

# ── Save Session Info ────────────────────────────
cat > $SESSION_DIR/session_info.json << EOF
{
  "session_id"  : "$SESSION_ID",
  "start_time"  : "$(date)",
  "interface"   : "$INTERFACE",
  "local_ip"    : "$LOCAL_IP",
  "gateway"     : "$GATEWAY",
  "subnet"      : "$SUBNET"
}
EOF

# ── Create Fresh Session Log Files ───────────────
> $SESSION_DIR/packets.json
> $SESSION_DIR/alerts.json
> $SESSION_DIR/ml_alerts.json

# ── Symlink to current session ───────────────────
ln -sf $(pwd)/$SESSION_DIR/packets.json \
       logs/current_packets.json
ln -sf $(pwd)/$SESSION_DIR/alerts.json \
       logs/current_alerts.json
ln -sf $(pwd)/$SESSION_DIR/ml_alerts.json \
       logs/current_ml_alerts.json

echo ""
echo "📊 Fresh session logs created!"

# ── Update Snort HOME_NET ────────────────────────
echo ""
echo "🔧 Updating Snort config..."
sudo sed -i \
  "s|HOME_NET = '[^']*'|HOME_NET = '$SUBNET'|" \
  /etc/snort/snort.lua
echo "   ✅ HOME_NET = $SUBNET"

# ── Start Snort ──────────────────────────────────
echo ""
echo "🚀 Starting components..."
sudo snort -c /etc/snort/snort.lua \
     -i $INTERFACE \
     -l /var/log/snort \
     -s 65535 -k none \
     > /tmp/snort.log 2>&1 &
SNORT_PID=$!
echo "   ✅ Snort running (PID: $SNORT_PID)"

# ── Start Dashboard ──────────────────────────────
source venv/bin/activate
SESSION_ID=$SESSION_ID \
venv/bin/python3 dashboard/app.py \
    > /tmp/dashboard.log 2>&1 &
DASH_PID=$!
echo "   ✅ Dashboard running (PID: $DASH_PID)"
echo "   🌐 Open: http://127.0.0.1:5000"

sleep 2
echo ""
echo "================================================"
echo "🛡️  IDS ACTIVE — Session: $SESSION_ID"
echo "🌐 Dashboard  → http://127.0.0.1:5000"
echo "⏹️  Press Ctrl+C to stop"
echo "================================================"
echo ""

# ── Start Packet Capture ─────────────────────────
SESSION_LOG_DIR=$SESSION_DIR \
sudo -E venv/bin/python3 src/packet_capture.py

# ── On Exit — Save Session Summary ───────────────
echo ""
echo "🛑 Shutting down session $SESSION_ID..."

# Save session end time
python3 -c "
import json, os
info_file = '$SESSION_DIR/session_info.json'
with open(info_file) as f:
    info = json.load(f)
info['end_time'] = '$(date)'

# Count totals
def count(f):
    try:
        return sum(1 for l in open(f) if l.strip())
    except: return 0

info['total_packets'] = count('$SESSION_DIR/packets.json')
info['total_alerts']  = count('$SESSION_DIR/alerts.json')
info['total_ml']      = count('$SESSION_DIR/ml_alerts.json')

with open(info_file, 'w') as f:
    json.dump(info, f, indent=2)
print(f'   📊 Session Summary:')
print(f'      Packets : {info[\"total_packets\"]}')
print(f'      Alerts  : {info[\"total_alerts\"]}')
print(f'      ML      : {info[\"total_ml\"]}')
"

sudo kill $SNORT_PID 2>/dev/null
kill $DASH_PID 2>/dev/null
echo "✅ Session $SESSION_ID saved!"
echo "📁 Logs: $SESSION_DIR"
echo "================================================"
