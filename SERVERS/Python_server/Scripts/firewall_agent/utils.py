import subprocess
import socket
import re
import psutil
from win32api import OpenProcess
from win32process import GetModuleFileNameEx
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ


def execute_command(command, success_message="Command executed successfully."):
    """Helper function to execute subprocess commands."""
    try:
        print("Executing command:", command)
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            print(success_message)
            return {"success": True, "message": success_message, "output": result.stdout.strip()}
        else:
            print("An error occurred:")
            print(result.stderr.strip())
            return {"success": False, "message": result.stderr.strip()}
    except Exception as e:
        print(f"Failed to execute command: {e}")
        return {"success": False, "message": str(e)}

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
            print("command", command)
            result = subprocess.run(command, capture_output=True, text=True)
            print("result", result)
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
        print("unique_ips", unique_ips)
        if unique_ips:
            print(f"Resolved IP addresses across all DNS servers: {', '.join(unique_ips)}")
            return unique_ips
        else:
            print("No IP addresses found from any DNS server.")
            return []

    except Exception as e:
        print(f"Error executing nslookup command: {e}")
        return []

def load_rules(agent):
    """Load firewall rules from central server"""
    try:
        # TODO: Implement API call to central server
        pass
    except Exception as e:
        print(f"Failed to load rules: {e}")

def is_allowed(agent, process_name, dst_ip, dst_port, protocol):
    """Check if traffic is allowed based on rules"""
    rules = agent.app_rules[process_name]
    
    if rules['blocked']:
        return False
        
    if dst_ip in rules['allowed_ips']:
        return True
        
    if dst_port in rules['allowed_ports']:
        return True
        
    return False

def log_traffic(agent, timestamp, process_name, dst_ip, dst_port, protocol, bytes_size):
    """Log traffic data for analysis"""
    agent.app_stats[process_name]['bytes_sent'] += bytes_size
    agent.app_stats[process_name]['connections'] += 1
    agent.app_stats[process_name]['last_activity'] = timestamp
    
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

def get_process_by_port(port):
    """Get process information by port"""
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr.port == port:
            try:
                process = psutil.Process(conn.pid)
                exe_path = get_process_exe_path(conn.pid)
                return process.name(), exe_path
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                return "Unknown", None
    return None, None

def get_process_exe_path(pid):
    """Get process executable path"""
    try:
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        return GetModuleFileNameEx(handle, 0)
    except Exception:
        return None