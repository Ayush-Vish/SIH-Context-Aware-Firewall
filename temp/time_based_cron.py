import schedule
import time
import datetime
import requests

# API endpoint and rules
API_URL = "https://central-admin.example.com/api"
ADD_RULES = {
    "action": "add",
    "rules": ["rule1", "rule2", "rule3"]  # Replace with your rules
}
REMOVE_RULES = {
    "action": "remove",
    "rules": ["rule1", "rule2", "rule3"]  # Replace with your rules
}

# Define start and end times
START_TIME = "09:00"  # Replace with desired start time (24-hour format)
END_TIME = "23:00"    # Replace with desired end time (24-hour format)

def add_firewall_rules():
    try:
        response = requests.post(f"{API_URL}/firewall/rules", json=ADD_RULES)
        if response.status_code == 200:
            print("Rules added successfully:", response.json())
        else:
            print("Failed to add rules:", response.text)
    except Exception as e:
        print(f"Error adding rules: {e}")

def remove_firewall_rules():
    try:
        response = requests.post(f"{API_URL}/firewall/rules", json=REMOVE_RULES)
        if response.status_code == 200:
            print("Rules removed successfully:", response.json())
        else:
            print("Failed to remove rules:", response.text)
    except Exception as e:
        print(f"Error removing rules: {e}")

def is_within_blocking_window():
    """Check if the current time falls within the blocking window."""
    now = datetime.datetime.now().time()
    start = datetime.datetime.strptime(START_TIME, "%H:%M").time()
    end = datetime.datetime.strptime(END_TIME, "%H:%M").time()
    return start <= now < end

# Initial check
if is_within_blocking_window():
    print("System started within blocking window. Ensuring rules are applied...")
    add_firewall_rules()
else:
    print("System started outside of blocking window. (Removing rules if active)...")

# Schedule jobs
schedule.every().day.at(START_TIME).do(add_firewall_rules)
schedule.every().day.at(END_TIME).do(remove_firewall_rules)

print("Firewall schedule is active. Press Ctrl+C to stop.")
try:
    while True:
        schedule.run_pending()
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopping the scheduler.")
