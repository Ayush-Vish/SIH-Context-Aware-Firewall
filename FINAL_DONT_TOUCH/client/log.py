import os
import time
import subprocess
import json
from shutil import copyfile

def parse_firewall_log_line(line):
    """
    Parse a single line from the Windows Firewall log.

    Returns a dictionary with details of the log entry or None for invalid lines.
    """
    parts = line.strip().split()
    if len(parts) < 9:
        return None

    return {
        "date": parts[0],
        "time": parts[1],
        "action": parts[2],
        "protocol": parts[3],
        "source_ip": parts[4],
        "destination_ip": parts[5],
        "source_port": parts[6],
        "destination_port": parts[7],
        "size": parts[8]
    }

def get_firewall_rules():
    """
    Fetch all Windows Firewall rules using PowerShell and return them as a list of dictionaries.
    """
    command = [
        "powershell",
        "-Command",
        "Get-NetFirewallRule | Get-NetFirewallPortFilter | ConvertTo-Json -Depth 2"
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        rules = json.loads(result.stdout)
        print(rules[0])
        css_rules = [rule for rule in rules if rule.get("Name", "").startswith("CSS")]
        return css_rules
    except Exception as e:
        print(f"Error fetching firewall rules: {e}")
        return []

def match_log_to_rule(log_entry, rules):
    """
    Match a log entry to a firewall rule.

    Returns the matching rule or None if no match is found.
    """
    for rule in rules:
        if rule.get("Enabled", "").lower() != "true":
            continue

        # Match protocol
        if log_entry["protocol"].lower() != rule.get("Protocol", "").lower():
            continue

        # Match ports
        local_port = rule.get("LocalPort")
        if isinstance(local_port, str):
            local_ports = local_port.split(",")  # Split string into list
        elif isinstance(local_port, list):
            local_ports = local_port  # Already a list
        else:
            local_ports = []  # Default to empty list if type is unexpected

        if log_entry["destination_port"] not in local_ports:
            continue

        # Match remote IP (if specified in rule)
        remote_address = rule.get("RemoteAddress", "")
        if isinstance(remote_address, str):
            remote_ips = remote_address.split(",")  # Split string into list
        elif isinstance(remote_address, list):
            remote_ips = remote_address  # Already a list
        else:
            remote_ips = []  # Default to empty list if type is unexpected

        if remote_ips and log_entry["destination_ip"] not in remote_ips:
            continue

        return rule
    return None

def backup_log_file(log_path, backup_dir):
    """
    Backup the current log file to a timestamped file in the backup directory.
    """
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_path = os.path.join(backup_dir, f"firewall_log_{timestamp}.log")
    copyfile(log_path, backup_path)
    print(f"Backup created: {backup_path}")

def monitor_firewall_logs(log_path, backup_dir, max_size_kb=32):
    """
    Monitor the Windows Firewall log for dropped packets and synchronize before the size limit.
    """
    print(f"Monitoring firewall log at {log_path}...")

    if not os.path.exists(log_path):
        print("Firewall log file not found. Ensure logging is enabled.")
        return

    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    rules = get_firewall_rules()
    if not rules:
        print("No CSS-prefixed firewall rules fetched. Ensure you have permissions.")
        return

    print(f"Fetched {len(rules)} CSS-prefixed rules.")
    last_position = 0

    while True:
        # Check log file size
        log_size_kb = os.path.getsize(log_path) / 1024
        if log_size_kb >= max_size_kb:
            print(f"Log file size exceeds {max_size_kb} KB. Backing up and resetting log...")
            backup_log_file(log_path, backup_dir)
            # Clear the log after backup
            open(log_path, "w").close()

        with open(log_path, "r") as log_file:
            log_file.seek(last_position)
            for line in log_file:
                if line.startswith("#"):
                    # Skip comment lines in the log file
                    continue

                event = parse_firewall_log_line(line)
                if event and event["action"].lower() == "drop":
                    print("\n[Packet Dropped]")
                    print(f"Date: {event['date']} {event['time']}")
                    print(f"Protocol: {event['protocol']}")
                    print(f"Source IP: {event['source_ip']}")
                    print(f"Destination IP: {event['destination_ip']}")
                    print(f"Source Port: {event['source_port']}")
                    print(f"Destination Port: {event['destination_port']}")

                    # Match to a CSS-prefixed rule
                    matching_rule = match_log_to_rule(event, rules)
                    if matching_rule:
                        print("\n[Matching Rule Found]")
                        print(f"Name: {matching_rule.get('Name', 'Unknown')}")
                        print(f"Direction: {matching_rule.get('Direction', 'Unknown')}")
                        print(f"Protocol: {matching_rule.get('Protocol', 'Unknown')}")
                        print(f"Local Port: {matching_rule.get('LocalPort', 'Unknown')}")
                        print(f"Remote Address: {matching_rule.get('RemoteAddress', 'Unknown')}")
                    else:
                        print("\n[No Matching CSS Rule Found]")
            
            last_position = log_file.tell()

        time.sleep(1)  # Poll for new log entries every second

if __name__ == "__main__":
    FIREWALL_LOG_PATH = r"C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"
    BACKUP_DIR = r"C:\\Windows\\System32\\LogFiles\\Firewall\\Backups"
    monitor_firewall_logs(FIREWALL_LOG_PATH, BACKUP_DIR)
