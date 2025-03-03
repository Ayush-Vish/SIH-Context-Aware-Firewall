import os
import sys
import subprocess

def is_admin():
    """
    Check if the script is running with administrator privileges.
    """
    return os.geteuid() == 0 if sys.platform != 'win32' else bool(subprocess.run('NET SESSION', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE))

def enable_firewall_logging():
    """
    Enable Windows Firewall logging for all profiles (Domain, Private, and Public).
    """
    try:
        # Commands to enable logging for dropped packets and successful connections
        commands = [
            "Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -LogFileName 'C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log'",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -LogMaxSizeKilobytes 4096"
        ]

        for cmd in commands:
            subprocess.run(["powershell", "-Command", cmd], check=True)
        
        print("Windows Firewall logging enabled successfully.")
        print("Log file location: C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log")
    
    except subprocess.CalledProcessError as e:
        print(f"Error enabling firewall logging: {e}")
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")

def run_as_admin():
    """
    Re-launch the script with administrator privileges.
    """
    if sys.platform == "win32":
        # On Windows, use PowerShell to relaunch the script with admin rights
        # We run the powershell command again, this time using "runAs" to get elevated rights
        script = sys.argv[0]
        params = ' '.join(sys.argv[1:])
        subprocess.run(["powershell", "Start-Process", "python", script, "-ArgumentList", params, "-Verb", "runAs"])
    else:
        print("Administrator privileges are not supported on this OS for this operation.")
        sys.exit(1)

if __name__ == "__main__":
    if not is_admin():
        print("Administrator privileges required. Re-launching with admin privileges...")
        run_as_admin()
    else:
        enable_firewall_logging()
