import psutil
from win32api import OpenProcess
from win32process import GetModuleFileNameEx
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
import pydivert
import datetime
import json
import socket
import requests
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

if __name__ == "__main__":
    agent = FirewallAgent()
    try:
        agent.monitor_traffic()
    except KeyboardInterrupt:
        print("\nStopping firewall agent...")