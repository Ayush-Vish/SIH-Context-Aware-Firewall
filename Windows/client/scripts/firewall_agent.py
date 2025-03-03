import subprocess
import os
import sys
import time

class FirewallAgent:
     def __init__(self):
          self.PORT_PROTOCOL_MAP = {
            80: "HTTP", 443: "HTTPS", 53: "DNS",
            21: "FTP", 22: "SSH", 25: "SMTP",
            110: "POP3", 143: "IMAP"
            }
          self.rules = []
     def execute_command(self ,command, success_message="Command executed successfully."):
        """Helper function to execute subprocess commands."""
        try:
            print("Executing command:", command)
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                print(success_message)
                print(result.stdout.strip())
                print(type(result.stdout.strip()))
                return {"success": True, "message": result.stdout.strip(), "data":result.stdout.strip()}
            else:
                print("An error occurred:")
                return {"success": False, "message": result.stderr.strip()}
        except Exception as e:
            print(f"Failed to execute command: {e}")
            return {"success": False, "message": str(e)}