import subprocess
import re
import requests
import time
import psutil
import logging
import os
import threading

API_KEY = "f04ae8a8b3b3b1"
VPN_API_URL = "https://ipinfo.io/"
CHECK_INTERVAL = 30  # Time interval (in seconds) to recheck

vpn_detected_flag = threading.Event()

def get_active_connections():
    """Fetch active network connections using psutil."""
    connections = psutil.net_connections(kind='inet')
    remote_ips = set()

    for conn in connections:
        # Ensure raddr (remote address) is not None before accessing the IP
        if conn.raddr:
            ip = conn.raddr.ip
            if ip and not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")):
                remote_ips.add(ip)

    return remote_ips

def check_vpn_proxy(ip):
    """Check if an IP is a VPN or proxy using the ipinfo API."""
    try:
        response = requests.get(f"{VPN_API_URL}/{ip}?token={API_KEY}")
        data = response.json()
        
        privacy = data.get("privacy",{})
        is_vpn = privacy.get("vpn",False)
        is_proxy = privacy.get("proxy",False)
        
        return is_vpn or is_proxy
    except requests.exceptions.RequestException :
        return False

def monitor_connections():
    """Continuously monitor outgoing connections and log VPN usage."""
    seen_ips = set()
    while True:
        remote_ips = get_active_connections()
        new_ips = remote_ips - seen_ips

        for ip in new_ips:
            if check_vpn_proxy(ip):
                vpn_detected_flag.set()
                vpn_detected_flag.ip = ip
        seen_ips = remote_ips
        time.sleep(CHECK_INTERVAL)

def start_vpn_monitoring():
    """Start VPN monitoring in a separate thread."""
    vpn_thread = threading.Thread(target=monitor_connections, daemon=True)
    vpn_thread.start()