import socketio
import psutil
from scripts.start import getAdminEmail , changeAdminEmail
from scripts.static_info import collect_device_info

class Client:
    def __init__(self):
        self.socket = socketio.Client()
        #self.firewallAgent = FirewallAgent()
        self.identity = {
            'adminID': None,
            'clientID': None,
            'socketID': None
        }
        #events
        self.socket.on("connect",self.on_connect)
        self.socket.on("message",self.on_message)
        self.socket.on("disconnect",self.on_disconnect)
    def start(self):
        while True:
            try:
                user_choice = input("1. Start Client \n2. Change Admin \n").strip()

                if user_choice == "2":
                    adminEmail = changeAdminEmail()
                    print(f"admin email changed to: {adminEmail}")
                elif user_choice == "1":
                    adminEmail = getAdminEmail()
                    self.socket.connect("http://localhost:3000", auth={"adminEmail": adminEmail})
                    self.socket.wait()
                else:
                    print("invalid choice. please enter 1 or 2.")

            except KeyboardInterrupt:
                print("disconnected due to keyboard interrupt.")
                break
            except Exception as e:
                print(f"error: {e}")
                break
    
    @staticmethod
    def get_mac_address():
        mac_addresses = []
        for _, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK: 
                    mac_addresses.append(addr.address)
        return mac_addresses
    
    def on_connect(self):
        print("connected to admin")

    def on_message(self,data):
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
        print("disconnected from admin")

    def send_mac_details(self):
        mac_addresses = self.get_mac_address()
        self.socket.emit("mac-address",{"mac": mac_addresses,"identity": self.identity})
        print("mac address sent to admin")

    def send_static_details(self):
        result = collect_device_info()
        self.socket.emit("static-details",{"static": result, "identity": self.identity})
        print("static data send to admin")

if __name__ == "__main__":
    client = Client()
    client.start()