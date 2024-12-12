import psutil
import requests
import os
import platform
import socket
import time
from datetime import datetime
from .domain_mapping import get_domain_mapping
from .application_data import get_application_details

def get_active_connections(exclude_system=True):
    system_processes = [
        "systemd", "init", "kthreadd", "ksoftirqd", "kworker", "rcu_sched",
        "migration", "watchdog", "kswapd", "ps", "bash", "sh", "dhclient",
        "NetworkManager", "dbus-daemon", "avahi-daemon", "cron", "atd",
        "udevd", "systemd-journald", "systemd-logind", "systemd-udevd"
    ]

    connections = psutil.net_connections(kind='inet')
    active_connections = []

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

        protocol = 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'

        if exclude_system and process_name.lower() in [p.lower() for p in system_processes]:
            continue

        active_connections.append({
            "pid": pid if pid else 'N/A',
            "protocol": protocol,
            "local_address": local_addr,
            "remote_address": remote_addr,
            "status": status,
            "process_name": process_name
        })

    return active_connections

def get_interfaces_info():
    interfaces = psutil.net_if_addrs()
    interface_details = psutil.net_if_stats()
    interfaces_info = []

    for interface_name, addrs in interfaces.items():
        description = interface_details.get(interface_name, None)
        is_up = description.isup if description else False
        interface_info = {
            "interface": interface_name,
            "status": "Up" if is_up else "Down",
            "addresses": [],
            "mtu": description.mtu if description else "N/A"
        }

        for addr in addrs:
            if addr.family == socket.AF_INET:
                interface_info["addresses"].append({"type": "IPv4", "address": addr.address})
            elif addr.family == socket.AF_INET6:
                interface_info["addresses"].append({"type": "IPv6", "address": addr.address})
            elif addr.family == psutil.AF_LINK:
                interface_info["addresses"].append({"type": "MAC", "address": addr.address})

        interfaces_info.append(interface_info)

    return interfaces_info

def get_public_ip():
    try:
        response = requests.get('https://icanhazip.com', timeout=5)
        public_ip = response.text.strip()
        return public_ip
    except requests.exceptions.RequestException as e:
        print(f"Error getting public IP: {e}")
        return None

def get_device_info():
    device_name = socket.gethostname()
    os_name = platform.system()
    os_version = platform.version()
    os_release = platform.release()

    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    uptime_days = int(uptime_seconds // (24 * 3600))
    uptime_hours = int((uptime_seconds % (24 * 3600)) // 3600)
    uptime_minutes = int((uptime_seconds % 3600) // 60)

    cpu_cores = psutil.cpu_count(logical=True)
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    total_memory = memory_info.total / (1024 ** 3)
    used_memory = memory_info.used / (1024 ** 3)
    available_memory = memory_info.available / (1024 ** 3)

    return {
        "device_name": device_name,
        "os": f"{os_name} {os_release} (Version: {os_version})",
        "public_ip": get_public_ip(),
        "uptime": {
            "days": uptime_days,
            "hours": uptime_hours,
            "minutes": uptime_minutes
        },
        "cpu_info": {
            "cpu_cores": cpu_cores,
            "cpu_usage": cpu_usage
        },
        "memory_info": {
            "total_memory": total_memory,
            "used_memory": used_memory,
            "available_memory": available_memory
        }
    }

def get_packet_byte_device_usage_info():
    net_io = psutil.net_io_counters()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return {
        "time_of_report": current_time,
        "bytes_sent": net_io.bytes_sent,
        "bytes_received": net_io.bytes_recv,
        "packets_sent": net_io.packets_sent,
        "packets_received": net_io.packets_recv
    }

def get_running_processes(exclude_system=True):
    system_processes = [
        "systemd", "init", "kthreadd", "ksoftirqd", "kworker", "rcu_sched",
        "migration", "watchdog", "kswapd", "bash", "sh", "cron", "atd"
    ]

    running_processes = []

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            exe = proc.info['exe']

            if exclude_system and name.lower() in [p.lower() for p in system_processes]:
                continue

            running_processes.append({
                "pid": pid,
                "process_name": name,
                "exe": exe
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return running_processes

def get_open_ports():
    connections = psutil.net_connections(kind='inet')
    open_ports = []

    for conn in connections:
        if conn.status == 'LISTEN':
            port = conn.laddr.port
            pid = conn.pid

            try:
                process = psutil.Process(pid)
                process_name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "N/A"

            open_ports.append({
                "port": port,
                "pid": pid,
                "process_name": process_name
            })

    return open_ports

def collect_device_info():
    device_info = get_device_info()
    active_connections = get_active_connections()
    interfaces_info = get_interfaces_info()
    network_usage = get_packet_byte_device_usage_info()
    running_processes = get_running_processes()
    open_ports = get_open_ports()
    domain_mapping = get_domain_mapping()
    application_data = get_application_details()

    result = {
        "device_info": device_info,
        "active_connections": active_connections,
        "network_interfaces": interfaces_info,
        "network_usage": network_usage,
        "running_processes": running_processes,
        "open_ports": open_ports,
        "domain_mapping": domain_mapping,
        "application_data": application_data
    }
    print(result)
    return result

if __name__ == "__main__":
    collect_device_info()
