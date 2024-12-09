import uuid
from .utils import execute_command, get_ip_from_domain

def add_application_rules(agent, rules=None):
    try:
        if not rules or not isinstance(rules, list):
            raise ValueError("Rules must be provided as a list of rule configurations")

        results = []
        for rule_config in rules:
            print(rule_config)
            # Validate required fields
            required_fields = ["rule_name", "domain", "app_path", "direction"]
            if not all(field in rule_config for field in required_fields):
                raise ValueError(f"Missing required fields. Required: {required_fields}")

            rule_name = rule_config["rule_name"]
            rule_name = "CSS__" + rule_name + "__" + str(uuid.uuid4())
            domain = rule_config["domain"]
            app_path = rule_config["app_path"]
            direction = rule_config["direction"].lower()
            ports = rule_config.get("ports", [])
            action = rule_config.get("action", "block").lower()

            if direction not in ['inbound', 'outbound']:
                raise ValueError(f"Invalid direction '{direction}' for rule '{rule_name}'")
            
            if action not in ['allow', 'block']:
                raise ValueError(f"Invalid action '{action}' for rule '{rule_name}'")
            print(rule_name, domain, app_path, direction, ports, action)
            # Get IPs for domain
            ip_addresses = get_ip_from_domain(domain)
            print("IP addresses", ip_addresses)
            if not ip_addresses:
                results.append({
                    "rule_name": rule_name,
                    "status": "error",
                    "message": f"Failed to resolve domain '{domain}'"
                })
                continue

            # Format IP addresses into a comma-separated string
            ip_list = ','.join(ip_addresses)
            direction_flag = "in" if direction == "inbound" else "out"
            action_flag = "allow" if action == "allow" else "block"
            print(ip_list)
            if not ports:
                # Create single rule for all IPs without port specification
                base_command = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    f"dir={direction_flag}",
                    f"action={action_flag}",
                    f"program={app_path}",
                    f"remoteip={ip_list}",
                    "enable=yes"
                ]
                print(base_command)
                
                result = execute_command(base_command)
                results.append({
                    "rule_name": rule_name,
                    "ips": ip_list,
                    "status": "success" if result["success"] else "error",
                    "message": result["message"]
                })
            else:
                # Create rules for each port, but combine IPs
                for port in ports:
                    port_rule_name = f"{rule_name}_port{port}"
                    port_command = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={port_rule_name}",
                        f"dir={direction_flag}",
                        f"action={action_flag}",
                        f"program={app_path}",
                        f"remoteip={ip_list}",
                        f"localport={port}",
                        "protocol=TCP",
                        "enable=yes"
                    ]
                    
                    
                    result = execute_command(port_command)
                    results.append({
                        "rule_name": port_rule_name,
                        "ips": ip_list,
                        "port": port,
                        "status": "success" if result["success"] else "error",
                        "message": result["message"]
                    })
        print(results)
        return {"results": results}, 200

    except ValueError as ve:
        return {"error": str(ve)}, 400
    except Exception as e:
        return {"error": f"Error while adding application rules: {str(e)}"}, 500

def add_port_rule(agent, rules=None):
    try:
        if not rules or not isinstance(rules, list):
            raise ValueError("Rules must be provided as a list of rule configurations")

        results = []
        for rule_config in rules:
            print("Processing rule:", rule_config)
            # Validate required fields
            required_fields = ["name", "port", "protocol", "action", "direction"]
            if not all(field in rule_config for field in required fields):
                raise ValueError(f"Missing required fields. Required: {required_fields}")

            name = rule_config["name"]
            port = rule_config["port"]
            protocol = rule_config["protocol"].strip().upper()
            action = rule_config["action"].strip().lower()
            direction = rule_config["direction"].strip().lower()

            try:
                port = int(port)
            except ValueError:
                print("Invalid port number. Please enter a valid integer.")
                results.append({"name": name, "status": "error", "message": "Invalid port number"})
                continue

            if protocol not in ["TCP", "UDP", "BOTH"]:
                print("Invalid protocol. Use 'TCP', 'UDP', or 'Both'.")
                results.append({"name": name, "status": "error", "message": "Invalid protocol"})
                continue

            if action not in ["allow", "block"] or direction not in ["inbound", "outbound"]:
                print("Invalid action or direction. Use 'Allow'/'Block' and 'Inbound'/'Outbound'.")
                results.append({"name": name, "status": "error", "message": "Invalid action or direction"})
                continue

            action_flag = "allow" if action == "allow" else "block"
            direction_flag = "in" if direction == "inbound" else "out"

            if protocol == "BOTH":
                # Create rules for both TCP and UDP
                for proto in ["TCP", "UDP"]:
                    command = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={name}_{proto}",
                        f"dir={direction_flag}",
                        f"action={action_flag}",
                        f"protocol={proto}",
                        f"localport={port}",
                        "enable=yes"
                    ]
                    result = execute_command(command, success_message=f"Port rule '{name}_{proto}' on port {port}/{proto} added successfully.")
                    results.append(result)
            else:
                # Create rule for single protocol
                command = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={name}",
                    f"dir={direction_flag}",
                    f"action={action_flag}",
                    f"protocol={protocol}",
                    f"localport={port}",
                    "enable=yes"
                ]
                result = execute_command(command, success_message=f"Port rule '{name}' on port {port}/{protocol} added successfully.")
                results.append(result)

        return {"results": results}, 200

    except ValueError as ve:
        return {"error": str(ve)}, 400
    except Exception as e:
        return {"error": f"Error while adding port rules: {str(e)}"}, 500

def add_domain_rules(agent, rules=None):
    try:
        print(rules)
        print("Inside add_domain_rules")
        if not rules or not isinstance(rules, list):
            raise ValueError("Rules must be provided as a list of rule configurations")

        results = []
        for rule_config in rules:
            print("rule_config", rule_config)
            # Validate required fields
            required_fields = ["rule_name", "domain", "direction"]
            if not all field in rule_config for field in required fields):
                raise ValueError(f"Missing required fields. Required: {required_fields}")

            rule_name = "CSS__" + rule_config["rule_name"] + "__" + str(uuid.uuid4())
            domain = rule_config["domain"]
            direction = rule_config["direction"].lower()
            action = rule_config.get("action", "block").lower()
            ports = rule_config.get("ports", [])
            print(rule_name, domain, direction, action, ports)
            if direction not in ['inbound', 'outbound']:
                raise ValueError(f"Invalid direction '{direction}' for rule '{rule_name}'")
            
            if action not in ['allow', 'block']:
                raise ValueError(f"Invalid action '{action}' for rule '{rule_name}'")

            # Get IPs for domain
            print("Domain", domain)
            ip_addresses = get_ip_from_domain(domain)
            print("IP addresses", ip_addresses)
            if not ip_addresses:
                results.append({
                    "rule_name": rule_name,
                    "status": "error",
                    "message": f"Failed to resolve domain '{domain}'"
                })
                continue

            # Combine all IPs into a comma-separated string
            ip_list = ','.join(ip_addresses)
            direction_flag = "in" if direction == "inbound" else "out"
            action_flag = "allow" if action == "allow" else "block"
            print("---------------", ip_list, direction_flag, action_flag, ports)
            if not ports:
                # Create a single rule for all IPs without port specification
                base_command = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    f"dir={direction_flag}",
                    f"action={action_flag}",
                    f"remoteip={ip_list}",
                    "enable=yes"
                ]

                result = execute_command(base_command)
                results.append({
                    "rule_name": rule_name,
                    "domain": domain,
                    "ips": ip_list,
                    "status": "success" if result["success"] else "error",
                    "message": result["message"]
                })
            else:
                # Create a single rule per port that includes all IPs
                for port in ports:
                    port_rule_name = f"{rule_name}_port{port}"
                    port_command = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={port_rule_name}",
                        f"dir={direction_flag}",
                        f"action={action_flag}",
                        f"remoteip={ip_list}",
                        f"localport={port}",
                        "protocol=TCP",
                        "enable=yes"
                    ]
                    
                    result = execute_command(port_command)
                    results.append({
                        "rule_name": port_rule_name,
                        "domain": domain,
                        "ips": ip_list,
                        "port": port,
                        "status": "success" if result["success"] else "error",
                        "message": result["message"]
                    })
        print(results)
        return {"results": results}, 200

    except ValueError as ve:
        print(ve)
        return {"error": str(ve)}, 400
    except Exception as e:
        print(e)
        return {"error": f"Error while adding domain rules: {str(e)}"}, 500