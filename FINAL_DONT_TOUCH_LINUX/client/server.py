import socketio
import psutil
from scripts.static_info import collect_device_info
from scripts.domain_mapping import start_dns_in_background
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
        
        # Events
        self.socket.on("connect", self.on_connect)
        self.socket.on("message", self.on_message)
        self.socket.on("disconnect", self.on_disconnect)
        self.socket.on("command", self.v2)
        

    def start(self):
        while True:
            try:
                    adminEmail = "palash@gmail.com"
                    self.socket.connect("http://localhost:3000", auth={"adminEmail": adminEmail})
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
    def block_ips_globally(self , data ) :
        print(data)
        ips = data.get("ips")
        self.firewallAgent.block_ip_globally(ips)
        self.socket.emit("response", {"response": "IP blocked", "identity": self.identity})
    def v2(self, data):
        print(data)
        rule_type = data.get("rule_type")
        domains = data.get("domains")
        ips =data.get("ips")
        results = []
        if(rule_type == "block_ips_globally"):
            results.append(self.firewallAgent.block_ips_addresses(domains ,ips , True))
        elif (rule_type == "block_app"):
            results.append(self.firewallAgent.blockapp (domains , ips , True) )
        elif (rule_type == "delete-rule"):
            results.append(self.firewallAgent.block_ips_addresses(domains ,ips , False))
        self.socket.emit("response", {"response": results, "identity": self.identity , "rule_type": rule_type})

if __name__ == "__main__":
    client = Client()
    client.start()
