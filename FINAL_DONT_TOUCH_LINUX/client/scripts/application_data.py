import psutil
import os
import time

processes_info = {}

def get_friendly_app_name(path):
    """
    Placeholder function to fetch friendly app names.
    For Linux, simply return the base name of the path.
    """
    return os.path.basename(path)

def format_uptime(seconds):
    """Converts uptime in seconds to a more readable format."""
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
    Fetches detailed information about a process.
    """
    try:
        process = psutil.Process(pid)
        uptime = time.time() - process.create_time()
        path = process.exe() if process.exe() else "N/A"
        name = get_friendly_app_name(path)
        process_info = {
            "name": name,
            "pid": pid,
            "path": path,
            "uptime": format_uptime(uptime),
            "total_bytes_sent": 0,
            "total_bytes_received": 0,
            "network_info": []  # Initialize as an empty list
        }
        
        # Get system-wide bytes sent and received (this is per system, not per process)
        net_io = psutil.net_io_counters()
        process_info["total_bytes_sent"] = net_io.bytes_sent
        process_info["total_bytes_received"] = net_io.bytes_recv

        return process_info
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def get_all_processes_info():
    """
    Iterates over all processes and updates process information.
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
    Collects details of all running applications in an array-like format.
    """
    get_all_processes_info()

    def convert_to_array(data):
        result = []
        for key, value in data.items():
            result.append({**value, 'process': key})
        return result

    return convert_to_array(processes_info)

# Example usage
if __name__ == "__main__":
    # Run the script with root (Linux) or administrator (Windows) privileges
    # On Linux: Use 'sudo python3 application_data.py' to avoid AccessDenied errors
    # On Windows: Run as Administrator to access process details and avoid restrictions
    app_details = get_application_details()
    for app in app_details:
        print(app)