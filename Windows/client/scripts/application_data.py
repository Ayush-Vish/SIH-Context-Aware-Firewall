import psutil
import os
import time
import win32api

processes_info = {}

def get_friendly_app_name(path):
    try:
        info = win32api.GetFileVersionInfo(path, "\\StringFileInfo\\040904b0\\FileDescription")
        return info
    except Exception:
        return os.path.splitext(os.path.basename(path))[0].capitalize()

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
    try:
        process = psutil.Process(pid)
        uptime = time.time() - process.create_time()
        path = process.exe()

        # Skip processes without valid paths
        if not path or path.lower().startswith("c:\\windows"):
            return None
        
        name = get_friendly_app_name(path)
        process_info = {
            "name": name,
            "pid": pid,
            "path": path,
            "uptime": format_uptime(uptime),
            "total_bytes_sent": 0,
            "total_bytes_received": 0,
        }
        
        # Get system-wide bytes sent and received (this is per system, not per process)
        net_io = psutil.net_io_counters()
        process_info["total_bytes_sent"] = net_io.bytes_sent
        process_info["total_bytes_received"] = net_io.bytes_recv

        return process_info
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def get_all_processes_info():
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
    get_all_processes_info()
    def convert_to_array(data):
        result = []
        for key, value in data.items():
            result.append({**value, 'process': key})
        return result
    return convert_to_array(processes_info)
