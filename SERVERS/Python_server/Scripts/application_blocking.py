from execute_command import execute_command
from get_ip_from_domain import get_ip_from_domain

def add_application_rule(rule_name_base,domain,app_path,direction):
    try:
        # Extract IPs using get_ip_from_domain
        ip_addresses = get_ip_from_domain(domain)
        if not ip_addresses:
            print(f"Failed to resolve domain '{domain}' to any IP address.")
            return

        print(f"Resolved IP addresses for '{domain}': {', '.join(ip_addresses)}")

        # Determine the direction flag
        direction_flag = "in" if direction == "inbound" else "out"

        for i, ip in enumerate(ip_addresses, start=1):
            # Create a unique rule name by appending a number to the base name
            rule_name = f"{rule_name_base}_{i}"

            # Firewall command to add a rule for each IP
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                f"dir={direction_flag}",
                "action=block",
                f"program={app_path}",
                f"remoteip={ip}",
                "enable=yes"
            ]

            # Execute the command
            execute_command(command, success_message=f"Application rule '{rule_name}' added successfully for IP {ip}.")

    except Exception as e:
        print(f"Error while adding application rule: {e}")