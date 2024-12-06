import psutil
from win32api import OpenProcess
from win32process import GetModuleFileNameEx
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
import pydivert
import datetime
import json
import socket
import subprocess


from collections import defaultdict


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
    def add_application_rules(self, rules=None):
        """
        Add application rules with combined IP ranges
        
        Expected rules format:
        rules = [
            {
                "rule_name": "rule1",
                "domain": "example.com",
                "app_path": "C:\\path\\to\\app.exe",
                "direction": "inbound",
                "ports": [80, 443],  # optional
                "action": "block"     # optional, defaults to block
            },
            # ... more rules ...
        ]
        """
        try:
            if not rules or not isinstance(rules, list):
                raise ValueError("Rules must be provided as a list of rule configurations")

            results = []
            for rule_config in rules:
                # Validate required fields
                required_fields = ["rule_name", "domain", "app_path", "direction"]
                if not all(field in rule_config for field in required_fields):
                    raise ValueError(f"Missing required fields. Required: {required_fields}")

                rule_name = rule_config["rule_name"]
                domain = rule_config["domain"]
                app_path = rule_config["app_path"]
                direction = rule_config["direction"].lower()
                ports = rule_config.get("ports", [])
                action = rule_config.get("action", "block").lower()

                if direction not in ['inbound', 'outbound']:
                    raise ValueError(f"Invalid direction '{direction}' for rule '{rule_name}'")
                
                if action not in ['allow', 'block']:
                    raise ValueError(f"Invalid action '{action}' for rule '{rule_name}'")

                # Get IPs for domain
                ip_addresses = self.get_ip_from_domain(domain)
                if not ip_addresses:
                    results.append({
                        "rule_name": rule_name,
                        "status": "error",
                        "message": f"Failed to resolve domain '{domain}'"
                    })
                    continue

                # Format IP addresses into a comma-separated string
                ip_list = ','.join(ip_addresses)
                direction_flag = "in" if direction == "inbound" else "out"
                action_flag = "allow" if action == "allow" else "block"

                if not ports:
                    # Create single rule for all IPs without port specification
                    base_command = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}",
                        f"dir={direction_flag}",
                        f"action={action_flag}",
                        f"program={app_path}",
                        f"remoteip={ip_list}",
                        "enable=yes"
                    ]
                    
                    result = self.execute_command(base_command)
                    results.append({
                        "rule_name": rule_name,
                        "ips": ip_list,
                        "status": "success" if result["success"] else "error",
                        "message": result["message"]
                    })
                else:
                    # Create rules for each port, but combine IPs
                    for port in ports:
                        port_rule_name = f"{rule_name}_port{port}"
                        port_command = [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={port_rule_name}",
                            f"dir={direction_flag}",
                            f"action={action_flag}",
                            f"program={app_path}",
                            f"remoteip={ip_list}",
                            f"localport={port}",
                            "protocol=TCP",
                            "enable=yes"
                        ]
                        
                        result = self.execute_command(port_command)
                        results.append({
                            "rule_name": port_rule_name,
                            "ips": ip_list,
                            "port": port,
                            "status": "success" if result["success"] else "error",
                            "message": result["message"]
                        })

            return {"results": results}, 200

        except ValueError as ve:
            return {"error": str(ve)}, 400
        except Exception as e:
            return {"error": f"Error while adding application rules: {str(e)}"}, 500
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
    def add_domain_rules(self, rules=None):
        """
        Add multiple domain rules at once
        
        Expected rules format:
        rules = [
            {
                "rule_name": "rule1",
                "domain": "example.com",
                "direction": "outbound",
                "action": "block",
                "ports": [80, 443]  # optional
            },
            # ... more rules ...
        ]
        """
        try:
            if not rules or not isinstance(rules, list):
                raise ValueError("Rules must be provided as a list of rule configurations")

            results = []
            for rule_config in rules:
                # Validate required fields
                required_fields = ["rule_name", "domain", "direction", "action"]
                if not all(field in rule_config for field in required_fields):
                    raise ValueError(f"Missing required fields. Required: {required_fields}")

                rule_name = rule_config["rule_name"]
                domain = rule_config["domain"]
                direction = rule_config["direction"].lower()
                action = rule_config["action"].lower()
                ports = rule_config.get("ports", [])

                if direction not in ['inbound', 'outbound']:
                    raise ValueError(f"Invalid direction '{direction}' for rule '{rule_name}'")
                
                if action not in ['allow', 'block']:
                    raise ValueError(f"Invalid action '{action}' for rule '{rule_name}'")

                # Get IPs for domain
                ip_addresses = self.get_ip_from_domain(domain)
                if not ip_addresses:
                    results.append({
                        "rule_name": rule_name,
                        "status": "error",
                        "message": f"Failed to resolve domain '{domain}'"
                    })
                    continue

                # Combine all IPs into a comma-separated string
                ip_list = ','.join(ip_addresses)
                direction_flag = "in" if direction == "inbound" else "out"
                action_flag = "allow" if action == "allow" else "block"

                if not ports:
                    # Create a single rule for all IPs without port specification
                    base_command = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}",
                        f"dir={direction_flag}",
                        f"action={action_flag}",
                        f"remoteip={ip_list}",
                        "enable=yes"
                    ]

                    result = self.execute_command(base_command)
                    results.append({
                        "rule_name": rule_name,
                        "domain": domain,
                        "ips": ip_list,
                        "status": "success" if result["success"] else "error",
                        "message": result["message"]
                    })
                else:
                    # Create a single rule per port that includes all IPs
                    for port in ports:
                        port_rule_name = f"{rule_name}_port{port}"
                        port_command = [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={port_rule_name}",
                            f"dir={direction_flag}",
                            f"action={action_flag}",
                            f"remoteip={ip_list}",
                            f"localport={port}",
                            "protocol=TCP",
                            "enable=yes"
                        ]
                        
                        result = self.execute_command(port_command)
                        results.append({
                            "rule_name": port_rule_name,
                            "domain": domain,
                            "ips": ip_list,
                            "port": port,
                            "status": "success" if result["success"] else "error",
                            "message": result["message"]
                        })

            return {"results": results}, 200

        except ValueError as ve:
            return {"error": str(ve)}, 400
        except Exception as e:
            return {"error": f"Error while adding domain rules: {str(e)}"}, 500
    


