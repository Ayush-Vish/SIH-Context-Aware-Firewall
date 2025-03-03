import sys
import subprocess
import re

def get_ip_from_domain(domain):
    # List of popular DNS servers
    dns_servers = [
        "8.8.8.8",      # Google DNS
        "8.8.4.4",      # Google DNS Secondary
        "1.1.1.1",      # Cloudflare
        "1.0.0.1",      # Cloudflare Secondary
        "9.9.9.9",      # Quad9
        "208.67.222.222", # OpenDNS
        "208.67.220.220"  # OpenDNS Secondary
    ]
    
    all_ips = set()  # Use set to automatically handle duplicates
    
    try:
        for dns_server in dns_servers:
            # Run nslookup command with specific DNS server
            command = ["nslookup", domain, dns_server]
            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"nslookup command failed for DNS {dns_server}: {result.stderr}")
                continue

            # Extract IP addresses using regex
            output = result.stdout
            ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # Matches IPv4 addresses
            ip_addresses = re.findall(ip_pattern, output)

            # Add valid IPs to set
            for ip in ip_addresses:
                # Exclude DNS server IPs and localhost
                if not ip.startswith('127.') and ip not in dns_servers:
                    all_ips.add(ip)

        # Convert set to list
        unique_ips = list(all_ips)
        
        if unique_ips:
            print(f"Resolved IP addresses across all DNS servers: {', '.join(unique_ips)}")
            return unique_ips
        else:
            print("No IP addresses found from any DNS server.")
            return []

    except Exception as e:
        print(f"Error executing nslookup command: {e}")
        return []

# Make the function directly importable
sys.modules[__name__] = get_ip_from_domain

