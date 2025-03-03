import os

def create_or_read_config():
    folder_path = "C:/CSS"
    file_path = os.path.join(folder_path, "css.conf")

    # Create folder if it doesn't exist
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    admin_email = None  # Variable to store admin email

    # Check if file exists
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            print("Reading config file...")
            for line in file:
                if line.startswith("admin_email="):
                    admin_email = line.split("=", 1)[1].strip()
                    break
    else:
        admin_email = input("Enter Admin Email: ").strip()
        with open(file_path, "w") as file:
            file.write(f"admin_email={admin_email}\n")
        print("Config file created and admin email saved.")

    print("Admin Email:", admin_email)
    return admin_email

if __name__ == "__main__":
    admin_email = create_or_read_config()
