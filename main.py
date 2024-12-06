import psutil
from win32api import OpenProcess
from win32process import GetModuleFileNameEx
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
import pydivert
import datetime
import json
import socket
import subprocess
import requests
import get_ip_from_domain
from collections import defaultdict
import threading

class FirewallAgent:
    def __init__(self):
        # Basic protocol mapping
        self.PORT_PROTOCOL_MAP = {
            80: "HTTP", 443: "HTTPS", 53: "DNS",
            21: "FTP", 22: "SSH", 25: "SMTP",
            110: "POP3", 143: "IMAP"
        }
        
        # Application rules storage
        self.app_rules = defaultdict(lambda: {
            'allowed_ips': set(),
            'allowed_domains': set(),
            'allowed_ports': set(),
            'blocked': False
        })
        
        # Traffic statistics for anomaly detection
        self.app_stats = defaultdict(lambda: {
            'bytes_sent': 0,
            'connections': 0,
            'last_activity': None
        })
        
        self.load_rules()
    
    def load_rules(self):
        """Load firewall rules from central server"""
        try:
            # TODO: Implement API call to central server
            pass
        except Exception as e:
            print(f"Failed to load rules: {e}")

    def is_allowed(self, process_name, dst_ip, dst_port, protocol):
        """Check if traffic is allowed based on rules"""
        rules = self.app_rules[process_name]
        
        if rules['blocked']:
            return False
            
        if dst_ip in rules['allowed_ips']:
            return True
            
        if dst_port in rules['allowed_ports']:
            return True
            
        return False

    def log_traffic(self, timestamp, process_name, dst_ip, dst_port, protocol, bytes_size):
        """Log traffic data for analysis"""
        self.app_stats[process_name]['bytes_sent'] += bytes_size
        self.app_stats[process_name]['connections'] += 1
        self.app_stats[process_name]['last_activity'] = timestamp
        
        # TODO: Send logs to central server
        log_data = {
            'timestamp': timestamp,
            'process': process_name,
            'destination': dst_ip,
            'port': dst_port,
            'protocol': protocol,
            'bytes': bytes_size
        }
        
        # Async log sending would go here

    def monitor_traffic(self):
        """Main traffic monitoring loop"""
        print("Starting Application Firewall Agent...")
        with pydivert.WinDivert("tcp or udp") as w:
            for packet in w:
                try:
                    if packet.is_outbound:
                        process_name, exe_path = self.get_process_by_port(packet.src_port)
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        protocol = self.PORT_PROTOCOL_MAP.get(packet.dst_port, "Other")
                        transport_protocol = "TCP" if packet.tcp else "UDP"
                        
                        # Check if traffic is allowed
                        if self.is_allowed(process_name, packet.dst_addr, packet.dst_port, protocol):
                            # Log the allowed traffic
                            self.log_traffic(
                                timestamp, process_name, packet.dst_addr,
                                packet.dst_port, protocol, len(packet.payload)
                            )
                            
                            print(
                                f"[{timestamp}] [ALLOWED] [{transport_protocol}] "
                                f"Process: {process_name} ({exe_path}) -> "
                                f"IP: {packet.dst_addr}, Port: {packet.dst_port}, "
                                f"Protocol: {protocol}, "
                                f"Size: {len(packet.payload)} bytes"
                            )
                            w.send(packet)
                        else:
                            print(
                                f"[{timestamp}] [BLOCKED] [{transport_protocol}] "
                                f"Process: {process_name} -> {packet.dst_addr}:{packet.dst_port}"
                            )
                            # Don't send packet if blocked
                            continue

                except Exception as e:
                    print(f"Error processing packet: {e}")
                    w.send(packet)

    def get_process_by_port(self, port):
        """Get process information by port"""
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr.port == port:
                try:
                    process = psutil.Process(conn.pid)
                    exe_path = self.get_process_exe_path(conn.pid)
                    return process.name(), exe_path
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    return "Unknown", None
        return None, None

    def get_process_exe_path(self, pid):
        """Get process executable path"""
        try:
            handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            return GetModuleFileNameEx(handle, 0)
        except Exception:
            return None
    def add_application_rule(self):
        try:
            rule_name_base = input("Enter a base name for the rule: ").strip()
            domain = input("Enter domain to block (e.g., example.com): ").strip()
            app_path = input("Enter application path (e.g., C:\\MyApp.exe): ").strip()
            direction = input("Enter direction (Inbound/Outbound): ").strip().lower()

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
                self.execute_command(command, success_message=f"Application rule '{rule_name}' added successfully for IP {ip}.")

        except Exception as e:
            print(f"Error while adding application rule: {e}")
    def add_port_rule(self):
        name = input("Enter rule name: ").strip()
        try:
            port = int(input("Enter port number: ").strip())
        except ValueError:
            print("Invalid port number. Please enter a valid integer.")
            return

        protocol = input("Enter protocol (TCP/UDP/Both): ").strip().upper()
        if protocol not in ["TCP", "UDP", "BOTH"]:
            print("Invalid protocol. Use 'TCP', 'UDP', or 'Both'.")
            return

        action = input("Enter action (Allow/Block): ").strip().lower()
        direction = input("Enter direction (Inbound/Outbound): ").strip().lower()

        if action not in ["allow", "block"] or direction not in ["inbound", "outbound"]:
            print("Invalid action or direction. Use 'Allow'/'Block' and 'Inbound'/'Outbound'.")
            return

        action_flag = "allow" if action == "allow" else "block"
        direction_flag = "in" if direction == "inbound" else "out"

        if protocol == "BOTH":
            # Create rules for both TCP and UDP
            for proto in ["TCP", "UDP"]:
                command = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={name}_{proto}",
                    f"dir={direction_flag}",
                    f"action={action_flag}",
                    f"protocol={proto}",
                    f"localport={port}",
                    "enable=yes"
                ]
                self.execute_command(command, success_message=f"Port rule '{name}_{proto}' on port {port}/{proto} added successfully.")
        else:
            # Create rule for single protocol
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}",
                f"dir={direction_flag}",
                f"action={action_flag}",
                f"protocol={protocol}",
                f"localport={port}",
                "enable=yes"
                ]
            self.execute_command(command, success_message=f"Port rule '{name}' on port {port}/{protocol} added successfully.")
    def list_all_rules(self):
        command = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
        self.execute_command(command, success_message="Firewall rules listed below:")

    def remove_rule_by_name(self):
        name = input("Enter rule name to remove: ").strip()
        command = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        self.execute_command(command, success_message=f"Rule '{name}' removed successfully.")
    def execute_command(self ,command, success_message="Command executed successfully."):
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
    def add_domain_rule(self):
        try:
            rule_name_base = input("Enter a base name for the rule: ").strip()
            domain = input("Enter domain to block (e.g., example.com): ").strip()

            # Get the list of IPs for the domain
            ip_addresses = get_ip_from_domain(domain)

            if not ip_addresses:
                print(f"No IPs found for domain '{domain}'. Cannot create rules.")
                return

            for i, ip in enumerate(ip_addresses, start=1):
                # Create a unique rule name by appending a number to the base name
                rule_name = f"{rule_name_base}_{i}"

                # Firewall command to add a rule for each IP
                command = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=out",  # Outbound direction
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes"
                ]

                # Execute the command
                self.execute_command(command, success_message=f"Domain rule '{rule_name}' added successfully for IP {ip}.")

        except Exception as e:
            print(f"Error while adding domain rule: {e}")    
    

if __name__ == "__main__":
    agent = FirewallAgent()
    try:
        print("Starting firewall agent...")
    except KeyboardInterrupt:
        print("\nStopping firewall agent...")