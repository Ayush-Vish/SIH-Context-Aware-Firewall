import sys
import subprocess
import re


def get_ip_from_ping(domain):
    try:
        # Run the ping command
        command = ["ping", domain, "-n", "1"]  # For Windows; use "-c 1" on Linux
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Ping command failed: {result.stderr}")
            return []

        # Extract the IP address using regex
        output = result.stdout
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # Matches IPv4 addresses
        ip_addresses = re.findall(ip_pattern, output)

        if ip_addresses:
            print(f"Extracted IP addresses: {', '.join(ip_addresses)}")
            return ip_addresses
        else:
            print("No IP addresses found in the ping output.")
            return []

    except Exception as e:
        print(f"Error executing ping command: {e}")
        return []

sys.modules[__name__] = get_ip_from_ping