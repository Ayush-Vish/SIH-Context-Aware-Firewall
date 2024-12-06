import psutil
import geoip2.database
import time

# Path to GeoLite2 database
geoip_db_path = "../GeoLite-database/GeoLite2-Country.mmdb"

# Function to get the country code for an IP
def get_country(ip):
    reader = geoip2.database.Reader(geoip_db_path)
    try:
        response = reader.country(ip)
        return response.country.iso_code  # 2-letter country code
    except geoip2.errors.AddressNotFoundError:
        return None
    except ValueError:
        return None
    finally:
        reader.close()

# Function to terminate a process given its PID
def terminate_process(pid):
    try:
        process = psutil.Process(pid)
        process_name = process.name()  # Get process name before termination
        process.terminate()  # Attempt to terminate the process
        process.wait(timeout=5)  # Wait for the process to terminate
        print(f"Terminated process: PID={pid}, Name={process_name}")
    except psutil.NoSuchProcess:
        print(f"Process with PID {pid} does not exist.")
    except psutil.AccessDenied:
        print(f"Access denied to terminate process with PID {pid}. Run as administrator.")
    except Exception as e:
        print(f"Failed to terminate process PID {pid}: {e}")

# Function to monitor active connections and terminate processes for a specific country
def monitor_and_terminate_by_country(country_code):
    print(f"Monitoring active connections to terminate processes connecting to {country_code}...")
    while True:
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.raddr:  # Check if there's a remote address
                    remote_ip = conn.raddr.ip
                    pid = conn.pid

                    # Get the country of the remote IP
                    remote_country = get_country(remote_ip)

                    if remote_country == country_code:
                        print(f"Connection detected: IP={remote_ip}, PID={pid}, Country={remote_country}")
                        if pid:  # If the connection has an associated process ID
                            terminate_process(pid)
            time.sleep(5)  # Sleep to reduce CPU usage
        except KeyboardInterrupt:
            print("Monitoring stopped.")
            break
        except Exception as e:
            print(f"Error occurred: {e}")

# Example usage
if __name__ == "__main__":
    mode = input("Enter 'monitor' to monitor connections: ").strip().lower()
    if mode == "monitor":
        target_country = input("Enter the 2-letter country code to terminate processes connecting to: ").upper()
        monitor_and_terminate_by_country(target_country)
    else:
        print("Invalid mode selected.")
