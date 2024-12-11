import subprocess
import signal
import time
import os
import sys

# Full path to Suricata executable
SURICATA_PATH = r"C:\Program Files\Suricata\suricata.exe"

# Path to the virtual environment activation script
VENV_ACTIVATE = r"C:\Program Files\Suricata\.venv\Scripts\activate"

# Process IDs
suricata_proc = None
send_logs_proc = None
monitor_proc = None

def cleanup(signum, frame):
    print("Stopping all processes...")
    if suricata_proc:
        suricata_proc.terminate()
    if send_logs_proc:
        send_logs_proc.terminate()
    if monitor_proc:
        monitor_proc.terminate()
    if suricata_proc:
        suricata_proc.wait()
    if send_logs_proc:
        send_logs_proc.wait()
    if monitor_proc:
        monitor_proc.wait()
    print("All processes stopped.")
    sys.exit(0)

# Trap SIGINT (Ctrl+C) and call cleanup
signal.signal(signal.SIGINT, cleanup)

# Activate the virtual environment
activate_command = f'cmd.exe /c "{VENV_ACTIVATE} & python -c "import sys; print(sys.executable)"'
venv_python = subprocess.check_output(activate_command, shell=True).decode().strip()
print(f"Using Python interpreter from virtual environment: {venv_python}")

# Start Suricata
print("Starting Suricata...")
suricata_proc = subprocess.Popen([SURICATA_PATH, "-c", "suricata.yaml", "--windivert", "true"])
print(f"Started Suricata with PID: {suricata_proc.pid}")

# Wait for Suricata to initialize
time.sleep(2)

# Start send_logs.py
print("Starting send_logs.py...")
send_logs_proc = subprocess.Popen([venv_python, "send_logs.py"])
print(f"Started send_logs.py with PID: {send_logs_proc.pid}")

# Start monitor.py
print("Starting monitor.py...")
monitor_proc = subprocess.Popen([venv_python, "monitor.py"])
print(f"Started monitor.py with PID: {monitor_proc.pid}")

# Wait for all processes to finish
suricata_proc.wait()
send_logs_proc.wait()
monitor_proc.wait()