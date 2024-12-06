import psutil
import win32api
import os
import platform
import socket
import time
import win32com
from datetime import datetime

def get_active_connections():
    # Retrieve all active network connections (both TCP and UDP)
    connections = psutil.net_connections(kind='inet')

    print(f"{'PID':<10} {'Transport Layer Protocol':<30} {'Local Address':<30} {'Remote Address':<30} {'Status':<12} {'Service Name'}")

    for conn in connections:
        # Get the local and remote address information
        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        status = conn.status

        # Fetch the process ID (PID) of the connection and ensure it's an integer
        pid = conn.pid if conn.pid else None

        if pid:
            try:
                # Ensure PID is an integer before passing to Process
                pid = int(pid)
                process = psutil.Process(pid)
                process_name = process.name()
                service_name = "N/A"  # Placeholder for service name, as determining this can be complex
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                process_name = "N/A"
                service_name = "N/A"
        else:
            process_name = "N/A"
            service_name = "N/A"
        if(conn.type==1):
            protocol = 'tcp'
        else:
            protocol='udp'
        # Display the connection details
        print(f"{pid if pid else 'N/A':<10} {protocol:<30} {local_addr:<30} {remote_addr:<30} {status:<12} {process_name}")

def get_interfaces_info():
    interfaces = psutil.net_if_addrs()  # Get network interface addresses
    interface_details = psutil.net_if_stats()  # Get network interface stats (up/down, etc.)
    
    print("Network Interface Information:")
    for interface_name, addrs in interfaces.items():
        print(f"\nInterface: {interface_name}")
        
        # Retrieve description from interface details if available
        description = interface_details[interface_name].isup if interface_name in interface_details else "N/A"
        print(f"  Status: {'Up' if description else 'Down'}")
        
        for addr in addrs:
            # Check for IP address (IPv4/IPv6) and MAC address
            if addr.family == socket.AF_INET:
                print(f"  IP Address: {addr.address}")
            elif addr.family == socket.AF_INET6:
                print(f"  IPv6 Address: {addr.address}")
            elif addr.family == psutil.AF_LINK:
                print(f"  MAC Address: {addr.address}")
        
        # Retrieve additional description if available
        print(f"  Description: {interface_details[interface_name].mtu if interface_name in interface_details else 'N/A'}")


def get_device_info():
    # Get device name
    device_name = socket.gethostname()
    
    # Get OS information
    os_name = platform.system()
    os_version = platform.version()
    os_release = platform.release()
    
    # Get uptime in a human-readable format
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    uptime_days = int(uptime_seconds // (24 * 3600))
    uptime_hours = int((uptime_seconds % (24 * 3600)) // 3600)
    uptime_minutes = int((uptime_seconds % 3600) // 60)
    
    # Get CPU and memory information
    cpu_cores = psutil.cpu_count(logical=True)
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    total_memory = memory_info.total / (1024 ** 3)  # Convert to GB
    used_memory = memory_info.used / (1024 ** 3)  # Convert to GB
    available_memory = memory_info.available / (1024 ** 3)  # Convert to GB
    
    # Display device information
    print(f"Device Name: {device_name}")
    print(f"Operating System: {os_name} {os_release} (Version: {os_version})")
    print(f"Uptime: {uptime_days} days, {uptime_hours} hours, {uptime_minutes} minutes")
    print(f"CPU Cores: {cpu_cores}")
    print(f"CPU Usage: {cpu_usage}%")
    print(f"Total Memory: {total_memory:.2f} GB")
    print(f"Used Memory: {used_memory:.2f} GB")
    print(f"Available Memory: {available_memory:.2f} GB")


def get_packet_byte_device_usage_info():
    # Obtain network I/O statistics
    net_io = psutil.net_io_counters()
    
    # Get current time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Print network activity with time info
    print(f"Time of report: {current_time}")
    print(f"Bytes Sent: {net_io.bytes_sent}")
    print(f"Bytes Received: {net_io.bytes_recv}")
    print(f"Packets Sent: {net_io.packets_sent}")
    print(f"Packets Received: {net_io.packets_recv}")

def get_friendly_app_name(path):
    # Try to get the file description from the executable metadata
    try:
        info = win32api.GetFileVersionInfo(path, "\\StringFileInfo\\040904b0\\FileDescription")
        return info
    except Exception:
        # If no description is available, use the filename with capitalization as a fallback
        return os.path.splitext(os.path.basename(path))[0].capitalize()

def get_running_processes():
    # Retrieve and display all running processes with their IDs and friendly application names
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            exe = proc.info['exe']
            if exe:
                app_name = get_friendly_app_name(exe)
            else:
                app_name = "N/A"
            
            print(f"Process ID: {pid}, Process Name: {name}, Application Name: {app_name}, PATH:{exe}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def get_open_ports():
    # Retrieve all active network connections (both TCP and UDP)
    connections = psutil.net_connections(kind='inet')

    open_ports = {}

    # Loop through the connections and map the open ports to their details
    for conn in connections:
        # Check if the connection is using a valid port and is in LISTEN state
        if conn.status == 'LISTEN':
            port = conn.laddr.port
            pid = conn.pid

            try:
                # Get the process name using the PID
                process = psutil.Process(pid)
                process_name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "N/A"

            # Store the open port details in the dictionary
            open_ports[port] = {
                "pid": pid,
                "process_name": process_name
            }

    for port, details in open_ports.items():
        print(f"Port {port}: PID {details['pid']}, Process Name {details['process_name']}")
        

if __name__ == "__main__":
    # print("#############################################################################################################")
    # get_device_info()
    # print("#############################################################################################################")
    # get_interfaces_info()
    # print("#############################################################################################################")
    # get_packet_byte_device_usage_info()
    print("#############################################################################################################")
    get_running_processes()
    print("#############################################################################################################")
    # get_active_connections()
    # print("#############################################################################################################")
    # get_open_ports()
    # print("#############################################################################################################")



