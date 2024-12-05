import socketio
import get_ip_from_domain
import asyncio
import list_all_rules

# Flask Socket.IO client
sio = socketio.Client()

@sio.event
def connect():
    print("Connected to Node.js server!")

@sio.on("node-to-flask")
def handle_node_to_flask(data):
    print("Received from Node.js:", data)

    # Process the data and create a response
    response_data = {"processed": True, "original_data": data}
    
    # Emit response back to Node.js
    sio.emit("flask-response", response_data)
    print("Emitted")

@sio.on("get-ip-from-domain")
def  handle_get_ip_from_domain(domain):
    print("Received domain from Node.js:", domain)

    ip_array =  get_ip_from_domain(domain)
    print(ip_array)
    # # Emit response back to Node.js
    # sio.emit("get-ip-from-domain-response", ip_array)
    # print("Emitted")

@sio.event

def disconnect():
    print("Disconnected from Node.js server")

if __name__ == "__main__":
    sio.connect("http://localhost:3000")  # Connect to the Node.js server
    sio.wait()
