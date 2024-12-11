import socketio
import psutil
import threading
from scripts.start import getAdminEmail , changeAdminEmail
from scripts.static_info import collect_device_info
from scripts.domain_mapping import start_dns_in_background
from scripts.vpn import start_vpn_monitoring , vpn_detected_flag
from scripts.firewall_agent import FirewallAgent

class Client:
    def __init__(self):
        self.socket = socketio.Client()
        self.identity = {
            'adminID': None,
            'clientID': None,
            'socketID': None
        }
        self.firewallAgent = FirewallAgent()

        self.alert_thread = threading.Thread(target=self.monitor_vpn_alerts, daemon=True)
        
        # Events
        self.socket.on("connect", self.on_connect)
        self.socket.on("message", self.on_message)
        self.socket.on("disconnect", self.on_disconnect)
        self.socket.on("command", self.v2)

    def start(self):
        while True:
            try:
                user_choice = input("1. Start Client \n2. Change Admin \n").strip()

                if user_choice == "2":
                    adminEmail = changeAdminEmail()
                    print(f"Admin email changed to: {adminEmail}")
                elif user_choice == "1":
                    adminEmail = getAdminEmail()
                    self.socket.connect("http://localhost:3000", auth={"adminEmail": adminEmail})
                    self.socket.wait()
                else:
                    print("Invalid choice. Please enter 1 or 2.")

            except KeyboardInterrupt:
                print("Disconnected due to keyboard interrupt.")
                break
            except Exception as e:
                print(f"Error: {e}")
                break

    def monitor_vpn_alerts(self):
        """Monitor VPN detected flag and handle alerts."""
        while True:
            if vpn_detected_flag.is_set():
                ip = getattr(vpn_detected_flag, "ip", None)
                print(f"VPN/Proxy detected: {ip}")
                self.socket.emit("alert", {"ip": ip, "identity": self.identity, "type": "vpn-alert"})
                vpn_detected_flag.clear()  # Reset the flag after handling
    
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
        start_vpn_monitoring()
    
    def on_connect(self):
        print("Connected to admin")
        self.start_background_processes()
        self.monitor_firewall_rules()  # Start monitoring firewall rules

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
        commands = data.get("commands")
        result = []
        for command in commands:
            result.append(self.firewallAgent.execute_command(command))
        self.socket.emit("response", {"response": result, "identity": self.identity , "rule_type": rule_type})

    # def monitor_firewall_rules(self):
    #     """
    #     Continuously monitor for triggered firewall rules and send alerts to the server.
    #     """
    #     print("Monitoring firewall rules...")
    #     for event in self.firewallAgent.monitor_events():  # Assuming monitor_events() yields events
    #         self.socket.emit("firewall-alert", {
    #             "rule": event["rule_name"],
    #             "source_ip": event["source_ip"],
    #             "destination_ip": event["destination_ip"],
    #             "action": event["action"],
    #             "identity": self.identity
    #         })
    #         print(f"Firewall alert sent: {event}")

if __name__ == "__main__":
    client = Client()
    client.start()
