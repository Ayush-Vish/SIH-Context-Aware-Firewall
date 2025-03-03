import subprocess
import socket  # Import socket module for domain resolution

def add_application_rule():
    name = input("Enter rule name: ").strip()
    domain = input("Enter domain to block (e.g., example.com): ").strip()
    app_path = input("Enter application path (e.g., C:\\MyApp.exe): ").strip()
    direction = input("Enter direction (Inbound/Outbound): ").strip().lower()

    # Validate direction input
    if direction not in ["inbound", "outbound"]:
        print("Invalid direction. Please enter 'Inbound' or 'Outbound'.")
        return

    # Resolve the domain to IP addresses
    try:
        ip_addresses = socket.gethostbyname_ex(domain)[2]
        if not ip_addresses:
            print(f"Failed to resolve domain '{domain}' to an IP address.")
            return
    except socket.gaierror as e:
        print(f"Error resolving domain '{domain}': {e}")
        return

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

    print(f"All resolved IPs for '{domain}' have been blocked for the application.")

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

if __name__ == "__main__":
    main()
