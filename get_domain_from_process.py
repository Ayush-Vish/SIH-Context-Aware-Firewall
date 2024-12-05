import psutil
from win32api import OpenProcess
from win32process import GetModuleFileNameEx
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
import pydivert


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


def capture_tcp_traffic():
    """
    Capture TCP traffic and map it to the originating process.
    """
    print("Starting TCP traffic sniffer...")
    with pydivert.WinDivert("tcp") as w:
        for packet in w:
            try:
                # Process only outbound packets
                if packet.is_outbound:
                    # Get the process by source port
                    process_name, exe_path = get_process_by_port(packet.src_port)
                    print(
                        f"[TCP] Process: {process_name} ({exe_path}) -> "
                        f"IP: {packet.dst_addr}, Port: {packet.dst_port}"
                    )

                # Re-inject the packet to ensure network flow
                w.send(packet)

            except Exception as e:
                print(f"Error processing packet: {e}")
                # Ensure the packet is re-injected even on error
                w.send(packet)


if __name__ == "__main__":
    try:
        capture_tcp_traffic()
    except KeyboardInterrupt:
        print("\nExiting...")
        
