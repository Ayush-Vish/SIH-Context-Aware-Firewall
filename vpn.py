import subprocess
import re
import requests
import time

API_KEY = "f04ae8a8b3b3b1"
VPN_API_URL = "https://ipinfo.io/"
CHECK_INTERVAL = 60  # Time interval (in seconds) to recheck

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
    """Check if an IP is a VPN or proxy using the ipinfo API."""
    try:
        response = requests.get(f"{VPN_API_URL}/{ip}?token={API_KEY}")
        data = response.json()
        
        # Extract privacy fields from the API response
        privacy = data.get("privacy", {})
        is_vpn = privacy.get("vpn", False)
        is_proxy = privacy.get("proxy", False)
        
        if is_vpn or is_proxy:
            return True
        return False
    except Exception as e:
        print(f"Error checking IP {ip}: {e}")
        return False

def monitor_connections():
    """Continuously monitor outgoing connections and log VPN usage."""
    seen_ips = set()
    while True:
        remote_ips = get_active_connections()
        new_ips = remote_ips - seen_ips

        for ip in new_ips:
            if check_vpn_proxy(ip):
                print(f"Alert: VPN or Proxy detected on IP {ip}")

        seen_ips = remote_ips
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    monitor_connections()
