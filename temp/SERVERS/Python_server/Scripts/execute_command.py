import subprocess

def execute_command(command, success_message="Command executed successfully."):
    """Helper function to execute subprocess commands."""
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            print(success_message)
            print(result.stdout.strip())
        else:
            print("An error occurred:")
            print(result.stderr.strip())
    except Exception as e:
        print(f"Failed to execute command: {e}")