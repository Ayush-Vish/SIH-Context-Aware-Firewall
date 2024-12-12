# batch_hosts_manager.py

import re
from .nethost import add, delete, isPresent


def add_multiple_entries(domain_ip_map):
    """Add multiple entries to the hosts file from a domain -> IP mapping."""
    
    for domain, ip in domain_ip_map.items():
        if isPresent(domain) == True:
            continue
        # Use the existing add function to add entries
        add(ip, domain)

def delete_map(domain_ip_map):
    """Delete multiple entries from the hosts file based on a domain -> IP mapping."""
    
    for domain in domain_ip_map.keys():
        if not isPresent(domain):
            print(f"{domain} does not exist in the hosts file. Skipping...")
            continue
        
        # Use the existing delete function to remove entries
        delete(domain)
        print(f"Deleted: {domain}")

# Example usage
if __name__ == "__main__":
    domain_ip_map = {
        "facebook.com": "1.1.1.1",
        "example.com": "2.2.2.2",
        "invalid-domain": "3.3.3.3",  # Invalid domain example
        "google.com": "256.256.256.256",  # Invalid IP example
    }
    
    add_multiple_entries(domain_ip_map)
