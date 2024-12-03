import subprocess
import socket
import get_ip_from_ping
def main():
    print("\n=== Welcome to the Advanced Firewall Agent ===")
    while True:
        print("\nChoose an option:")
        print("1. Add Application Rule")
        print("2. Add Port Rule")
        print("3. List All Rules")
        print("4. Remove Rule by Name")
        print("5. Monitor Network Traffic")
        print("6. Exit")

        try:
            option = int(input("Enter your choice: "))
        except ValueError:
            print("Invalid input. Please enter a valid number.")
            continue

        if option == 1:
            add_application_rule()
        elif option == 2:
            add_port_rule()
        elif option == 3:
            list_all_rules()
        elif option == 4:
            remove_rule_by_name()
        elif option == 5:
            monitor_network_traffic()
        elif option == 6:
            print("Exiting the Advanced Firewall Agent. Goodbye!")
            break
        else:
            print("Invalid option. Please choose a valid option from the menu.")

def add_application_rule():
    name = input("Enter rule name: ").strip()
    domain = input("Enter domain to block (e.g., example.com): ").strip()
    app_path = input("Enter application path (e.g., C:\\MyApp.exe): ").strip()
    direction = input("Enter direction (Inbound/Outbound): ").strip().lower()

    # Extract IPs using ping
    ip_addresses = get_ip_from_ping(domain)
    if not ip_addresses:
        print(f"Failed to resolve domain '{domain}' to any IP address.")
        return

    print(f"Resolved IP addresses for '{domain}': {', '.join(ip_addresses)}")

    # Prepare the firewall command
    direction_flag = "in" if direction == "inbound" else "out"

    for ip in ip_addresses:
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}",
            f"dir={direction_flag}",
            f"action=block",
            f"program={app_path}",
            f"remoteip={ip}",
            "enable=yes"
        ]
        execute_command(command, success_message=f"Application rule '{name}' added successfully for IP {ip}.")

def add_port_rule():
    name = input("Enter rule name: ").strip()
    try:
        port = int(input("Enter port number: ").strip())
    except ValueError:
        print("Invalid port number. Please enter a valid integer.")
        return

    protocol = input("Enter protocol (TCP/UDP): ").strip().upper()
    if protocol not in ["TCP", "UDP"]:
        print("Invalid protocol. Use 'TCP' or 'UDP'.")
        return

    action = input("Enter action (Allow/Block): ").strip().lower()
    direction = input("Enter direction (Inbound/Outbound): ").strip().lower()

    if action not in ["allow", "block"] or direction not in ["inbound", "outbound"]:
        print("Invalid action or direction. Use 'Allow'/'Block' and 'Inbound'/'Outbound'.")
        return

    action_flag = "allow" if action == "allow" else "block"
    direction_flag = "in" if direction == "inbound" else "out"

    command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        f"dir={direction_flag}",
        f"action={action_flag}",
        f"protocol={protocol}",
        f"localport={port}",
        "enable=yes"
    ]

    execute_command(command, success_message=f"Port rule '{name}' on port {port}/{protocol} added successfully.")

def list_all_rules():
    command = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
    execute_command(command, success_message="Firewall rules listed below:")

def remove_rule_by_name():
    name = input("Enter rule name to remove: ").strip()
    command = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
    execute_command(command, success_message=f"Rule '{name}' removed successfully.")

def monitor_network_traffic():

    print("\n=== Monitoring Network Traffic ===")
    print("This feature is under development. Future updates will include real-time monitoring.")

def execute_command(command, success_message="Command executed successfully."):
    """Helper function to execute subprocess commands."""
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            print(success_message)
            print(result.stdout.strip())
        else:
            print("An error occurred:")
            print(result.stderr.strip())
    except Exception as e:
        print(f"Failed to execute command: {e}")

if __name__ == "__main__":
    main()
