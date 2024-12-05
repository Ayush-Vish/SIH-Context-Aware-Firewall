import socketio
import uuid  # To get the MAC address
import psutil

from Scripts.get_ip_from_domain import get_ip_from_domain

sio = socketio.Client()

def get_all_mac_addresses():
    mac_addresses = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:  # AF_LINK corresponds to MAC addresses
                mac_addresses.append(addr.address)
    return mac_addresses

@sio.event
def connect():
    print("Connected to Node.js server!")
    send_macs()
    
def send_macs():
    all_mac_addresses = get_all_mac_addresses()
    sio.emit("mac-address", {"mac_address": all_mac_addresses})
    print(f"MAC address {all_mac_addresses} sent to Node.js server")


@sio.on("node-to-flask")
def handle_node_to_flask(data):
    print("Received from Node.js:", data)

    # Process the data and create a response
    response_data = {"processed": True, "original_data": data}
    
    # Emit response back to Node.js
    sio.emit("flask-response", response_data)
    print("Response emitted")

@sio.on("get_ip_from_domain")
def event_get_ip_from_domain(domain):
    print("Received from Node.js:", domain)
    response_data = get_ip_from_domain(domain)

    sio.emit("get_ip_from_domain_response", response_data)
    print("Response emitted")

@sio.event
def disconnect():
    print("Disconnected from Node.js server")

if __name__ == "__main__":
    try:
        sio.connect("http://localhost:3000")  # Connect to the Node.js server
        sio.wait()
    except Exception as e:
        print("An error occurred:", e)
