# ================================================
# Network IDS - Auto Snort Configuration
# Author: Ansh
# Automatically updates Snort config on any network
# ================================================

import subprocess
import os
import sys
from config import get_config, print_config

def update_snort_config(config):
    """Auto-update Snort HOME_NET based on current network"""

    snort_lua = "/etc/snort/snort.lua"

    print("🔧 Updating Snort configuration...")

    # Read current snort.lua
    with open(snort_lua, "r") as f:
        content = f.read()

    # Replace HOME_NET with current subnet
    import re
    new_content = re.sub(
        r"HOME_NET\s*=\s*'[^']*'",
        f"HOME_NET = '{config['subnet']}'",
        content
    )

    # Write updated config
    with open(snort_lua, "w") as f:
        f.write(new_content)

    print(f"   ✅ HOME_NET updated to: {config['subnet']}")

def validate_snort():
    """Validate Snort config"""
    print("\n🔍 Validating Snort config...")
    result = subprocess.run(
        ["snort", "-c", "/etc/snort/snort.lua", "-T"],
        capture_output=True, text=True
    )
    if "successfully validated" in result.stdout:
        print("   ✅ Snort config valid!")
        return True
    else:
        print("   ❌ Snort config error!")
        print(result.stderr)
        return False

def start_snort(config):
    """Start Snort with current interface"""
    print(f"\n🚀 Starting Snort on {config['interface']}...")
    cmd = [
        "snort",
        "-c", "/etc/snort/snort.lua",
        "-i", config["interface"],
        "-l", "/var/log/snort",
        "-s", "65535",
        "-k", "none"
    ]
    print(f"   Command: {' '.join(cmd)}")
    return cmd

def main():
    print("="*50)
    print("🛡️  Network IDS - Auto Snort Setup")
    print("="*50)

    # Get current network config
    config = get_config()
    print_config(config)

    # Check if running as root
    if os.geteuid() != 0:
        print("❌ Please run with sudo!")
        print("   sudo venv/bin/python3 setup_snort.py")
        sys.exit(1)

    # Update Snort config
    update_snort_config(config)

    # Validate
    if validate_snort():
        print("\n" + "="*50)
        print("✅ Snort is ready!")
        print("="*50)

        # Ask to start Snort
        answer = input("\nStart Snort now? (y/n): ")
        if answer.lower() == "y":
            cmd = start_snort(config)
            subprocess.run(["sudo"] + cmd)
    else:
        print("\n❌ Fix Snort config errors first!")
        # Handle --auto flag (no user input needed)
    if "--auto" in sys.argv:
        update_snort_config(config)
        validate_snort()
        return


if __name__ == "__main__":
    main()
