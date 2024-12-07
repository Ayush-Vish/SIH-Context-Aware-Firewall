import psutil
import time
import logging

# Configure logging
logging.basicConfig(filename='process_termination.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def log_process_termination(process_name, pid):
    logging.info(f"Process terminated: {process_name} (PID: {pid})")

def monitor_processes():
    monitored_processes = {proc.pid: proc.info['name'] for proc in psutil.process_iter(['pid', 'name'])}

    while True:
        current_processes = {proc.pid: proc.info['name'] for proc in psutil.process_iter(['pid', 'name'])}

        # Detect terminated processes
        terminated_pids = set(monitored_processes.keys()) - set(current_processes.keys())
        for pid in terminated_pids:
            process_name = monitored_processes[pid]
            log_process_termination(process_name, pid)
            print(f"Process terminated: {process_name} (PID: {pid})")

        # Update the monitored processes
        monitored_processes = current_processes

        time.sleep(1)

if __name__ == "__main__":
    monitor_processes()