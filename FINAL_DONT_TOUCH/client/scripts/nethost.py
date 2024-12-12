import os

# Path to the Windows hosts file
HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"

def add(ip, domain):
    """Add an IP address and its domain along with www subdomain to the hosts file."""
    entry = f"{ip} {domain} www.{domain}\n"
    
    # Read existing entries to check for duplicates
    with open(HOSTS_FILE_PATH, 'r') as hosts_file:
        lines = hosts_file.readlines()
    
    # Check if entry already exists
    for line in lines:
        if entry.strip() == line.strip():
            print(f"Entry already exists: {entry.strip()}")
            return
    
    # Append new entry to the hosts file
    with open(HOSTS_FILE_PATH, 'a') as hosts_file:
        hosts_file.write(entry)
    print(f"Added: {entry.strip()}")

def delete(domain):
    """Remove a domain and its www subdomain from the hosts file."""
    www_domain = f"www.{domain}"
    
    with open(HOSTS_FILE_PATH, 'r') as hosts_file:
        lines = hosts_file.readlines()
    
    with open(HOSTS_FILE_PATH, 'w') as hosts_file:
        for line in lines:
            if domain not in line and www_domain not in line:
                hosts_file.write(line)
            else:
                print(f"Removed: {line.strip()}")

def isPresent(domain):
    """Check if a domain or its www subdomain is present in the hosts file."""
    www_domain = f"www.{domain}"
    
    with open(HOSTS_FILE_PATH, 'r') as hosts_file:
        for line in hosts_file:
            if domain in line or www_domain in line:
                return True
    return False

if __name__ == "__main__":
    # Example usage
    add("1.1.1.1", "facebook.com")
    print(isPresent("facebook.com"))  # Should return True
    delete("facebook.com")
