#!/bin/bash
# ================================================
# Network IDS - Master Start Script
# Author: Ansh
# ================================================

clear
echo "================================================"
echo "🛡️  NETWORK INTRUSION DETECTION SYSTEM"
echo "================================================"

# ── Auto detect network ──────────────────────────
INTERFACE=$(ip route show default | awk '/default/ {print $5}')
LOCAL_IP=$(hostname -I | awk '{print $1}')
GATEWAY=$(ip route show default | awk '/default/ {print $3}')
SUBNET=$(ip route | grep -v default | grep $INTERFACE | awk '{print $1}' | head -1)

echo ""
echo "🔍 Network Detected:"
echo "   Interface : $INTERFACE"
echo "   Local IP  : $LOCAL_IP"
echo "   Gateway   : $GATEWAY"
echo "   Subnet    : $SUBNET"

# ── Update Snort HOME_NET ────────────────────────
echo ""
echo "🔧 Updating Snort config..."
sudo sed -i "s|HOME_NET = '[^']*'|HOME_NET = '$SUBNET'|" \
    /etc/snort/snort.lua
echo "   ✅ HOME_NET = $SUBNET"

# ── Start Snort silently ─────────────────────────
echo ""
echo "🚀 Starting components..."
sudo snort -c /etc/snort/snort.lua \
     -i $INTERFACE \
     -l /var/log/snort \
     -s 65535 -k none \
     > /tmp/snort.log 2>&1 &
SNORT_PID=$!
echo "   ✅ Snort running (PID: $SNORT_PID)"

# ── Start Dashboard silently ─────────────────────
source venv/bin/activate
venv/bin/python3 dashboard/app.py \
    > /tmp/dashboard.log 2>&1 &
DASH_PID=$!
echo "   ✅ Dashboard running (PID: $DASH_PID)"
echo "   🌐 Open browser: http://127.0.0.1:5000"

# ── Small delay then start capture ───────────────
sleep 2
echo "   ✅ Packet capture + ML starting..."
echo ""
echo "================================================"
echo "🛡️  IDS ACTIVE — Press Ctrl+C to stop"
echo "================================================"
echo ""

# ── Start packet capture (foreground) ────────────
sudo venv/bin/python3 src/packet_capture.py

# ── Cleanup ──────────────────────────────────────
echo ""
echo "🛑 Shutting down..."
sudo kill $SNORT_PID 2>/dev/null
kill $DASH_PID 2>/dev/null
echo "✅ All components stopped!"
echo "================================================"
