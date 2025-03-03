import { exec } from 'child_process';

const dns_servers = [
    "8.8.8.8",      // Google DNS
    "8.8.4.4",      // Google DNS Secondary
    "1.1.1.1",      // Cloudflare
    "1.0.0.1",      // Cloudflare Secondary
    "9.9.9.9",      // Quad9
    "208.67.222.222", // OpenDNS
    "208.67.220.220"  // OpenDNS Secondary
];

export const getIpFromDomain = async (domain) => {
    const all_ips = new Set();

    for (const dns_server of dns_servers) {
        const command = `nslookup ${domain} ${dns_server}`;
        console.log("command", command);

        try {
            const result = await execCommand(command);
            console.log("result", result);

            // Extract IP addresses using regex
            const ip_pattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;  // Matches IPv4 addresses
            const ip_addresses = result.match(ip_pattern);

            // Add valid IPs to set
            if (ip_addresses) {
                ip_addresses.forEach(ip => {
                    // Exclude DNS server IPs and localhost
                    if (!ip.startsWith('127.') && !dns_servers.includes(ip)) {
                        all_ips.add(ip);
                    }
                });
            }
        } catch (error) {
            console.log(`nslookup command failed for DNS ${dns_server}: ${error.message}`);
        }
    }

    const unique_ips = Array.from(all_ips);
    console.log("unique_ips", unique_ips);
    if (unique_ips.length > 0) {
        console.log(`Resolved IP addresses across all DNS servers: ${unique_ips.join(', ')}`);
        return unique_ips;
    } else {
        console.log("No IP addresses found from any DNS server.");
        return [];
    }
};

const execCommand = (command) => {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                reject(error);
            } else {
                resolve(stdout);
            }
        });
    });
};

export const generateNetshCommand = async (actionRule, rule, listType) => {
    const { rule_name, domain, app_path, action , direction, ports, protocol } = rule;
    const direction_flag = direction === "inbound" ? "in" : "out";
    const action_flag = action === "allow" ? "allow" : "block";
    
    const profile_flag = "profile=any"; // Specify the profile
    let base_command = [
        "netsh", "advfirewall", "firewall", actionRule === "delete" ? "delete" : "add", "rule",
        `name=${rule_name}`,
        `dir=${direction_flag}`,
        `action=${action_flag}`,
        profile_flag
    ];

    if (app_path) {
        base_command.push(`program="${app_path}"`);
    }

    if (domain) {
        const ip_addresses = await getIpFromDomain(domain);
        if (ip_addresses.length > 0) {
            base_command.push(`remoteip=${ip_addresses.join(',')}`);
        }
    }

    
    // Handle whitelist/blocklist specific logic
    const commands = [];

    if (listType === "whitelist") {
        // Block all connections except those in the whitelist
        const block_all_command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            `name=block_all_except_whitelist`,
            `dir=${direction_flag}`,
            `action=block`,
            profile_flag,
            `program="${app_path}"`,
            `remoteip=any`,
            "enable=yes",
        

        ];
        console.log("Generated command to block all except whitelist:", block_all_command.join(" "));
        commands.push(block_all_command.join(" "));
    } else if (listType === "blocklist") {
        // Allow all connections except those in the blocklist
        const allow_all_command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            `name=allow_all_except_blocklist`,
            `dir=${direction_flag}`,
            `action=allow`,
            profile_flag,
            `program="${app_path}"`,
            `remoteip=any`,
            "enable=yes",
           
        ];
        console.log("Generated command to allow all except blocklist:", allow_all_command.join(" "));
        commands.push(allow_all_command.join(" "));
    }

    if (ports && ports.length > 0) {
        ports.forEach(port => {
            let port_command = [...base_command];
            port_command.push(`localport=${port}`);
            port_command.push(`protocol=${protocol || "TCP"}`);
            port_command.push("enable=yes");
            console.log("Generated command:", port_command.join(" "));
            commands.push(port_command.join(" "));
        });
    } else {
        base_command.push("enable=yes");
        console.log("Generated command:", base_command.join(" "));
        commands.push(base_command.join(" "));
    }

    return commands;
};