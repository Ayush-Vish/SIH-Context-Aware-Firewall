import psutil
from win32api import OpenProcess
from win32process import GetModuleFileNameEx
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
import pydivert
import datetime

# Dictionary to map port numbers to protocols
PORT_PROTOCOL_MAP = {
    80: "HTTP",
    8080: "HTTP",
    443: "HTTPS",
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    53: "DNS",
    # Add more ports and protocols as needed
}

def get_process_by_port(port):
    """
    Map a port to the process using it.
    Returns the process name and executable path.
    """
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr.port == port:
            pid = conn.pid
            try:
                process = psutil.Process(pid)
                exe_path = get_process_exe_path(pid)
                return process.name(), exe_path
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                return "Unknown", None
    return None, None

def get_process_exe_path(pid):
    """
    Get the full path of the process executable for the given PID.
    """
    try:
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        exe_path = GetModuleFileNameEx(handle, 0)
        return exe_path
    except Exception:
        return None
def capture_network_traffic():
    """
    Capture both TCP and UDP traffic and map it to the originating process.
    """
    print("Starting network traffic sniffer...")
    # Capture both TCP and UDP packets
    with pydivert.WinDivert("tcp or udp") as w:
        for packet in w:
            try:
                if packet.is_outbound:
                    process_name, exe_path = get_process_by_port(packet.src_port)
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    protocol = PORT_PROTOCOL_MAP.get(packet.dst_port, "Other")
                    
                    # Determine if it's TCP or UDP
                    transport_protocol = "TCP" if packet.tcp else "UDP"
                    
                    print(
                        f"[{timestamp}] [{transport_protocol}] "
                        f"Process: {process_name} ({exe_path}) -> "
                        f"IP: {packet.dst_addr}, "
                        f"Port: {packet.dst_port}, "
                        f"Protocol: {protocol}, "
                        f"Payload Size: {len(packet.payload)} bytes"
                    )

                # Re-inject the packet
                w.send(packet)

            except Exception as e:
                print(f"Error processing packet: {e}")
                w.send(packet)

if __name__ == "__main__":
    try:
        capture_network_traffic()
    except KeyboardInterrupt:
        print("\nExiting...")