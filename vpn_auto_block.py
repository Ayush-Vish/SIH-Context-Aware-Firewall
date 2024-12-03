import subprocess
import re
import requests
import time

API_KEY = "09bf5934ac9c44fa88ff49be1273d827"
VPN_API_URL = "https://vpnapi.io/api/"
firewall_state = "allow"  # Tracks firewall state to avoid redundant changes


def get_active_connections():
    """Fetch active network connections using netstat."""
    result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
    connections = result.stdout
    remote_ips = set()

    for line in connections.splitlines():
        match = re.search(r"TCP\s+\S+:(\d+)\s+([\d.]+):\d+\s+\w+", line)
        if match:
            ip = match.group(2)
            if not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")):
                remote_ips.add(ip)

    return remote_ips


def check_vpn_proxy(ip):
    """Check if an IP is a VPN or proxy using the vpnapi.io API."""
    try:
        response = requests.get(f"{VPN_API_URL}{ip}?key={API_KEY}")
        data = response.json()
        if data.get("security", {}).get("vpn") or data.get("security", {}).get("proxy"):
            return True
        return False
    except Exception as e:
        print(f"Error checking IP {ip}: {e}")
        return False


def set_firewall_policy(policy):
    """Set the firewall policy."""
    global firewall_state
    if policy == "block" and firewall_state != "block":
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"])
        print("Firewall set to block all traffic.")
        firewall_state = "block"
    elif policy == "allow" and firewall_state != "allow":
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "allowinbound,allowoutbound"])
        print("Firewall set to allow all traffic.")
        firewall_state = "allow"


def monitor_connections():
    """Continuously monitor outgoing connections and adjust firewall rules."""
    seen_ips = set()
    while True:
        remote_ips = get_active_connections()
        new_ips = remote_ips - seen_ips
        flagged = False

        for ip in new_ips:
            if check_vpn_proxy(ip):
                flagged = True
                print(f"VPN detected on IP: {ip}. Blocking traffic.")
                break

        if flagged:
            set_firewall_policy("block")
        else:
            set_firewall_policy("allow")

        seen_ips = remote_ips
        time.sleep(5)  # Monitor connections every 5 seconds


def reevaluate_connections():
    """Temporarily lift the firewall block and check active connections for VPNs."""
    print("Reevaluating connections: Temporarily allowing traffic...")
    set_firewall_policy("allow")
    time.sleep(60)  # Allow traffic for one minute

    remote_ips = get_active_connections()
    flagged = False
            
    for ip in remote_ips:
        if check_vpn_proxy(ip):
            flagged = True
            print(f"VPN detected on IP: {ip}. Blocking traffic again.")
            break

    if flagged:
        set_firewall_policy("block")
    else:
        print("No VPN detected. Traffic remains allowed.")


if __name__ == "__main__":
    print("Starting VPN monitoring. Default state: Allow all traffic.")
    set_firewall_policy("allow")  # Default state is to allow traffic
    try:
        monitor_connections()
    except KeyboardInterrupt:
        print("\nStopping monitoring. Resetting firewall to allow traffic.")
        set_firewall_policy("allow")
