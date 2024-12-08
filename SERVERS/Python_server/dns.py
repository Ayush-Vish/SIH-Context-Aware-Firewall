from scapy.all import sniff, DNS, DNSQR
import psutil

# Dictionary to store the domains requested by each process
app_domains = {}

def capture_dns_requests(pkt):
    # Check if the packet contains DNS and is a query
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  # qr=0 means it's a query, not a response
        domain = pkt.getlayer(DNSQR).qname.decode()  # Extract the requested domain
        
        # Get the source port and the process associated with it
        src_port = pkt.getlayer("UDP").sport  # Source port
        process_name = get_process_by_port(src_port)
        
        if process_name:
            if process_name not in app_domains:
                app_domains[process_name] = []  # Initialize a list if not present
            app_domains[process_name].append(domain)  # Add the domain to the list for that process
            print_app_domains()

# Function to get the process name by port
def get_process_by_port(port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port and conn.pid:
            try:
                process = psutil.Process(conn.pid)
                return process.name()  # Return the process name
            except psutil.NoSuchProcess:
                pass
    return None  # Return None if no process is found for the port

# Function to print the current app -> [domains] mapping
def print_app_domains():
    for app, domains in app_domains.items():
        # Use set to avoid printing duplicate domains for the same process
        print(f"{app} -> {list(set(domains))}")
    print("-" * 50)

# Start sniffing, filter for DNS packets (UDP port 53)
sniff(filter="udp port 53", prn=capture_dns_requests, store=0)
