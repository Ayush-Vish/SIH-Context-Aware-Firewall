import psutil
import os
import time

# Dictionary to hold processes information with process names as keys
processes_info = {}

def get_friendly_app_name(path):
    """
    Retrieves a friendly name of the app from its executable path on Linux.
    If the file path does not have a description, returns the base name of the executable.
    """
    try:
        # Linux doesn't have a FileDescription like Windows, so we fall back to the executable name
        return os.path.basename(path)
    except Exception:
        return os.path.basename(path)

def format_uptime(seconds):
    """Converts uptime in seconds to a more readable format (days, hours, minutes, seconds)."""
    days = seconds // (24 * 3600)
    hours = (seconds % (24 * 3600)) // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    uptime_str = ""
    if days > 0:
        uptime_str += f"{days}d "
    if hours > 0:
        uptime_str += f"{hours}h "
    if minutes > 0:
        uptime_str += f"{minutes}m "
    uptime_str += f"{seconds}s"
    return uptime_str

def get_process_info(pid):
    """
    Fetches detailed information about a process using its PID.
    Returns a dictionary with process name, path, uptime, and network bytes.
    """
    try:
        process = psutil.Process(pid)
        uptime = time.time() - process.create_time()
        path = process.exe()  # Get the executable path
        name = get_friendly_app_name(path)
        process_info = {
            "name": name,
            "pid": pid,
            "path": path,
            "uptime": format_uptime(uptime),
            "total_bytes_sent": 0,
            "total_bytes_received": 0,
            "network_info": []  # Initialize as an empty list to hold network connection data
        }
        
        # Get system-wide bytes sent and received
        net_io = psutil.net_io_counters()
        process_info["total_bytes_sent"] = net_io.bytes_sent
        process_info["total_bytes_received"] = net_io.bytes_recv

        return process_info
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def get_active_connections():
    """
    Retrieves all active network connections and associates them with the respective process.
    Adds network connection information to the processes_info dictionary.
    """
    connections = psutil.net_connections(kind='inet')  # Get all internet connections

    for conn in connections:
        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        status = conn.status
        pid = conn.pid if conn.pid else None

        if pid:
            try:
                pid = int(pid)
                process = psutil.Process(pid)
                process_name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                process_name = "N/A"
        else:
            process_name = "N/A"
        
        protocol = 'tcp' if conn.type == 1 else 'udp'

        if process_name:
            if process_name not in processes_info:
                processes_info[process_name] = {}

            # Ensure network_info is initialized as a list in case the process info doesn't already have it
            if "network_info" not in processes_info[process_name]:
                processes_info[process_name]["network_info"] = []

            # Append each connection to the list in network_info
            processes_info[process_name]["network_info"].append({
                "protocol": protocol,
                "local_address": local_addr,
                "remote_address": remote_addr,
                "status": status
            })

def get_all_processes_info():
    """
    Retrieves information about all active processes on the system.
    Updates the `processes_info` dictionary.
    """
    for proc in psutil.process_iter(['pid', 'name']):
        pid = proc.info['pid']
        name = proc.info['name']
        process_info = get_process_info(pid)
        if process_info:
            if name not in processes_info:
                processes_info[name] = {}
            processes_info[name].update(process_info)
    
    return processes_info

def get_application_details():
    """
    Collects and returns details about all processes and their network connections.
    """
    get_all_processes_info()  # Collect information on all processes
    get_active_connections()   # Collect active connections data
    return []

if __name__ == "__main__":
    get_all_processes_info()  # First fill processes info
    get_active_connections()   # Then fill active connections info
    def convert_to_array():
        """
        Converts the processes info dictionary to a list format and prints it.
        """
        result = []
        for key, value in processes_info.items():
            result.append({**value, 'process': key})
        print(result)
    convert_to_array()