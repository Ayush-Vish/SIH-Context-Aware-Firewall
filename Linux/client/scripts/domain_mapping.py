import threading
from scapy.all import sniff, DNS, DNSQR, UDP
import psutil
from datetime import datetime

# List to store the domain mapping objects with timestamps
app_domains = []

def get_domain_mapping():
    return app_domains

def capture_dns_requests(pkt):
    """
    Callback function to capture and process DNS requests.
    """
    # Check if the packet contains DNS and is a query
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  # qr=0 means it's a query, not a response
        domain = pkt.getlayer(DNSQR).qname.decode()  # Extract the requested domain
        
        # Get the source port and the process associated with it
        src_port = pkt[UDP].sport  # Source port
        process_name = get_process_by_port(src_port)
        
        if process_name:
            # Get the current timestamp when the domain is accessed
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Check if the process is already in the app_domains list
            for app in app_domains:
                if app['process_name'] == process_name:
                    # Check if the domain already exists for this process
                    if not any(entry['domain'] == domain for entry in app['domains']):
                        app['domains'].append({'domain': domain, 'timestamp': timestamp})  # Add the domain with timestamp
                    return
            
            # If the process is not found, add it to the list
            app_domains.append({
                'process_name': process_name,
                'domains': [{'domain': domain, 'timestamp': timestamp}]
            })

def get_process_by_port(port):
    """
    Get the process name by its network port.
    """
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port and conn.pid:
                try:
                    process = psutil.Process(conn.pid)
                    return process.name()  # Return the process name
                except psutil.NoSuchProcess:
                    return None
    except Exception as e:
        print(f"Error fetching process for port {port}: {e}")
    return None

def start_dns_sniffing():
    """
    Start sniffing DNS packets.
    """
    try:
        sniff(filter="udp port 53", prn=capture_dns_requests, store=0)
    except PermissionError:
        print("Permission denied. Please run as root or with administrator privileges.")
    except Exception as e:
        print(f"Error starting DNS sniffing: {e}")

def start_dns_in_background():
    """
    Start DNS sniffing in a background thread.
    """
    dns_thread = threading.Thread(target=start_dns_sniffing, daemon=True)
    dns_thread.start()

if __name__ == "__main__":
    start_dns_in_background()
    print("DNS sniffing started. Press Ctrl+C to stop.")
    
    try:
        # Keep the program running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping DNS sniffing...")