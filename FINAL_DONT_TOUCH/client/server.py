import os
import sys
import ctypes
import socketio
import psutil
import threading
from scripts.static_info import collect_device_info
from scripts.domain_mapping import start_dns_in_background
from scripts.vpn import start_vpn_monitoring, vpn_detected_flag
from scripts.firewall_agent import FirewallAgent
from scripts.globalblock import add_multiple_entries,delete_map

class Client:
    def __init__(self):
        self.socket = socketio.Client()
        self.identity = {
            'adminID': None,
            'clientID': None,
            'socketID': None
        }
        self.firewallAgent = FirewallAgent()
        
        # Events
        self.socket.on("connect", self.on_connect)
        self.socket.on("message", self.on_message)
        self.socket.on("disconnect", self.on_disconnect)
        self.socket.on("command", self.v2)

    def start(self):
        while True:
            try:
                adminEmail = "palash@gmail.com"
                self.socket.connect("http://13.203.78.23:3000", auth={"adminEmail": adminEmail})
                self.socket.wait()
            except KeyboardInterrupt:
                print("Disconnected due to keyboard interrupt.")
                break
            except Exception as e:
                print(f"Error: {e}")
                break
    
    @staticmethod
    def get_mac_address():
        mac_addresses = []
        for _, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK: 
                    mac_addresses.append(addr.address)
        return mac_addresses

    @staticmethod
    def start_background_processes():
        start_dns_in_background()    
    def on_connect(self):
        print("Connected to admin")
        self.start_background_processes()
    def on_message(self, data):
        print(data)
        for key in ['adminID', 'clientID', 'socketID']:
            if data.get("flags").get(key) is not None:
                self.identity[key] = data.get("flags").get(key)
        print(self.identity)
        if data.get("flags").get("sendMACDetails"):
            self.send_mac_details()
        if data.get("flags").get("sendStaticDetails"):
            self.send_static_details()

    def on_disconnect(self):
        print("Disconnected from admin")

    def send_mac_details(self):
        mac_addresses = self.get_mac_address()
        self.socket.emit("mac-address", {"mac": mac_addresses, "identity": self.identity})
        print("MAC address sent to admin")

    def send_static_details(self):
        result = collect_device_info()
        self.socket.emit("static-details", {"static": result, "identity": self.identity})
        print("Static data sent to admin")

    def v2(self, data):
        print(data)
        rule_type = data.get("rule_type")
        if rule_type == "delete_rule":
            domainToMap = data.get("domainToIpMap")
            delete_map(domainToMap)
        if rule_type == "domain_rules" or rule_type == "app_rules":
            domainToMap = data.get("domainToIpMap")
            add_multiple_entries(domainToMap)

        commands = data.get("commands")
        result = []
        
        for command in commands:
            result.append(self.firewallAgent.execute_command(command))
        
        self.socket.emit("response", {"response": result, "identity": self.identity , "rule_type": rule_type})

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Relaunch the script with administrative privileges."""
    if sys.platform == "win32":
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)

if __name__ == "__main__":
    if not is_admin():
        print("This script requires administrative privileges. Relaunching...")
        run_as_admin()
    else:
        client = Client()
        client.start()
