import socketio
import psutil
from Scripts.firewall_agent import FirewallAgent
from Scripts.device_static_info import collect_device_info

class CentralAdminClient:
    def __init__(self):
        self.sio = socketio.Client()
        self.adminID = None
        self.clientID = None
        self.socketID = None
        self.firewallAgent = FirewallAgent()

        # Bind event handlers
        self.sio.on("connect", self.on_connect)
        self.sio.on("message", self.on_message)
        self.sio.on("disconnect", self.on_disconnect)
        

    @staticmethod
    def get_all_mac_addresses():
        mac_addresses = []
        for _, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:  # AF_LINK corresponds to MAC addresses
                    mac_addresses.append(addr.address)
        return mac_addresses

    def on_connect(self):
        print("Connected to Central Admin Server")

    def on_message(self, data):
        # Update only if the value is not already set and data.get() is not None
        if data.get("socketID") is not None:
            self.socketID = data.get("socketID")
        if data.get("adminID") is not None:
            self.adminID = data.get("adminID")
        if data.get("clientID") is not None:
            self.clientID = data.get("clientID")
        print(data)

        if data.get("sendMACDetails"):
            self.send_macs()
        if data.get("sendStaticDetails"):
            self.send_static_data()

    def send_macs(self):
        all_mac_addresses = self.get_all_mac_addresses()
        self.sio.emit("mac-address", {"mac_address": all_mac_addresses, "adminID": self.adminID})
        print("MAC Addresses sent to Central Admin Server")

    def send_static_data(self):
        result = collect_device_info()
        self.sio.emit("static-data", {"clientID": self.clientID ,"static_data": result})
        print("Static data sent successfully")

    def on_disconnect(self):
        print("Disconnected from Central Admin Server")

    def start(self):
        try:
            adminEmail = input("Enter Admin Email: ")
            self.sio.connect("http://localhost:3000", auth={"adminEmail": adminEmail})
            self.sio.wait()
            
        except KeyboardInterrupt:
            print("Disconnected due to keyboard interrupt.")


if __name__ == "__main__":
    client = CentralAdminClient()
    client.start()
