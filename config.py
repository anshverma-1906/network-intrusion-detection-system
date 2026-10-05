# ================================================
# Network IDS - Auto Configuration
# Author: Ansh
# Detects network settings automatically
# ================================================

import subprocess
import socket
import json
import os

def get_interface():
    """Auto-detect active network interface"""
    try:
        # Get default interface
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True
        )
        # Extract interface name
        # Output: "default via x.x.x.x dev eth0"
        parts = result.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except:
        pass
    return "eth0"  # fallback

def get_local_ip():
    """Auto-detect local IP address"""
    try:
        s = socket.socket(socket.AF_INET,
                          socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_gateway():
    """Auto-detect gateway/router IP"""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True
        )
        # Output: "default via 192.168.1.1 dev eth0"
        parts = result.stdout.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    except:
        pass
    return None

def get_subnet():
    """Auto-detect subnet"""
    try:
        result = subprocess.run(
            ["ip", "addr", "show"],
            capture_output=True, text=True
        )
        for line in result.stdout.split("\n"):
            if "inet " in line and "127.0.0" not in line:
                # Extract subnet like 192.168.1.0/24
                addr = line.strip().split()[1]
                ip   = addr.split("/")[0]
                bits = addr.split("/")[1]
                parts = ip.split(".")
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/{bits}"
                return subnet
    except:
        pass
    return "192.168.1.0/24"

def get_config():
    """Get complete auto-detected config"""
    interface = get_interface()
    local_ip  = get_local_ip()
    gateway   = get_gateway()
    subnet    = get_subnet()

    config = {
        "interface" : interface,
        "local_ip"  : local_ip,
        "gateway"   : gateway,
        "subnet"    : subnet,
        "target_ip" : gateway or local_ip
    }

    return config

def print_config(config):
    """Print detected config"""
    print("\n" + "="*45)
    print("🔍 Auto-Detected Network Configuration")
    print("="*45)
    print(f"   Interface  : {config['interface']}")
    print(f"   Local IP   : {config['local_ip']}")
    print(f"   Gateway    : {config['gateway']}")
    print(f"   Subnet     : {config['subnet']}")
    print(f"   Target IP  : {config['target_ip']}")
    print("="*45 + "\n")

if __name__ == "__main__":
    config = get_config()
    print_config(config)
