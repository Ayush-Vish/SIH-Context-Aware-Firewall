import os from "os";
import { exec } from "child_process";

const dns_servers = [
    "8.8.8.8", // Google DNS
    "8.8.4.4", // Google DNS Secondary
    "1.1.1.1", // Cloudflare
    "1.0.0.1", // Cloudflare Secondary
    "9.9.9.9", // Quad9
    "208.67.222.222", // OpenDNS
    "208.67.220.220" // OpenDNS Secondary
];

export const execCommand = (command) => {
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

export const getIpFromDomain = async (domain) => {
    const all_ips = new Set();
    const isWindows = os.platform() !== "win32";
    const dns_server = dns_servers[0]; // Use the first DNS server by default
        const command = isWindows
            ? `nslookup ${domain} ${dns_server}`
            : `dig @${dns_server} ${domain} +short`;
        console.log("Command:", command);

        try {
            const result = await execCommand(command);
            console.log("Result:", result);

            // Extract IP addresses using regex
            const ip_pattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g; // Matches IPv4 addresses
            const ip_addresses = result.match(ip_pattern);

            // Add valid IPs to set
            if (ip_addresses) {
                ip_addresses.forEach((ip) => {
                    if (!ip.startsWith("127.") && !dns_servers.includes(ip)) {
                        all_ips.add(ip);
                    }
                });
            }
        } catch (error) {
            console.log(`Command failed for DNS ${dns_server}: ${error.message}`);
        }

    const unique_ips = Array.from(all_ips);
    console.log("Unique IPs:", unique_ips);
    return unique_ips[0];
};

export const getIpsFromDomains = async (domains) => {
    const all_ips = new Set();

    for (const domain of domains) {
        const ips = await getIpFromDomain(domain);
        ips.forEach((ip) => all_ips.add(ip));
    }

    const unique_ips = Array.from(all_ips);
    console.log("Unique IPs from Domains:", unique_ips);
    return unique_ips;
};

export const generateNetshCommand = async (actionRule, rule, listType) => {
    const { rule_name, domains, app_path, action, direction, ports, protocol, ip_addresses } = rule;
    const isWindows = os.platform() !== "win32";
    const commands = [];
    const direction_flag = direction === "inbound" ? (isWindows ? "in" : "INPUT") : (isWindows ? "out" : "OUTPUT");
    const action_flag = action === "allow" ? (isWindows ? "allow" : "-A") : (isWindows ? "block" : "-D");

    // Combine resolved IPs from domains and provided IP addresses
    const domainToIpMap = {};
    let resolved_ips = [];
    if (domains && domains.length > 0) {
        for (const domain of domains) {
            const ip = await getIpFromDomain(domain);
            if (ip) {
                resolved_ips.push(ip);
                domainToIpMap[domain] = ip;
            }
        }
    }

    const all_ips = [...resolved_ips, ...(ip_addresses || [])];
    if (isWindows) {
        let base_command = [
            "netsh", "advfirewall", "firewall", actionRule === "delete" ? "delete" : "add", "rule",
            `name=${rule_name}`,
            `dir=${direction_flag}`,
            `action=${action_flag}`,
            "profile=any"
        ];

        if (app_path) {
            base_command.push(`program="${app_path}"`);
        }

        if (all_ips.length > 0) {
            base_command.push(`remoteip=${all_ips.join(",")}`);
        }

        if (ports && ports.length > 0) {
            ports.forEach((port) => {
                const port_command = [...base_command, `localport=${port}`, `remoteport=${port}`, `protocol=${protocol || "TCP"}`, "enable=yes"];
                commands.push(port_command.join(" "));
            });
        } else {
            base_command.push("enable=yes");
            commands.push(base_command.join(" "));
        }
    } else {
        let base_command = ["iptables", action_flag, direction_flag];

        if (all_ips.length > 0) {
            all_ips.forEach((ip) => {
                const ip_command = [...base_command, `-s ${ip}`, `-j ${action === "allow" ? "ACCEPT" : "DROP"}`];
                commands.push(ip_command.join(" "));
            });
        }

        if (ports && ports.length > 0) {
            ports.forEach((port) => {
                const port_command = [...base_command, `--dport ${port}`, `-j ${action === "allow" ? "ACCEPT" : "DROP"}`];
                commands.push(port_command.join(" "));
            });
        } else {
            base_command.push(`-j ${action === "allow" ? "ACCEPT" : "DROP"}`);
            commands.push(base_command.join(" "));
        }
    }
    console.log(commands);

    return { commands, domainToIpMap };
};

export const getDomaintoIpMApping = async (domains) =>  {
    const domainToIpMap = {};
    for (const domain of domains) {
        const ips = await getIpFromDomain(domain);
        domainToIpMap[domain] = ips[0];
    }
    return domainToIpMap;
}

export function parseFirewallRules(inputString) {
    const rules = [];

    // Normalize line endings for cross-platform compatibility
    const normalizedInput = inputString.replace(/\r\n/g, '\n');

    // Split the input into blocks by "Rule Name:"
    const ruleBlocks = normalizedInput.split(/Rule Name:/).slice(1); // Skip the first empty part

    ruleBlocks.forEach((block) => {
        const rule = {};
        const lines = block.trim().split("\n");

        // Extract the Rule Name (first line of the block)
        rule["Rule Name"] = lines[0].trim();

        // Process the remaining lines for key-value pairs
        lines.slice(1).forEach((line) => {
            if (line.includes(":")) {
                const [key, ...valueParts] = line.split(":");
                const value = valueParts.join(":").trim(); // Handle cases where value contains ':'
                rule[key.trim()] = value;
            }
        });

        // Add the parsed rule to the list
        if (Object.keys(rule).length > 0) {
            rules.push(rule);
        }
    });

    return rules;
}

export function refineFirewallRule(rule) {
    const refinedRule = {};
    for (const [key, value] of Object.entries(rule)) {
        // Remove trailing backslashes (Windows-specific artifacts in some cases)
        let cleanedValue = value.replace(/\\+$/g, '');

        // Parse nested JSON-like strings if applicable
        try {
            cleanedValue = JSON.parse(cleanedValue);
        } catch {
            // If not JSON, use raw cleaned value
        }

        refinedRule[key] = cleanedValue;
    }
    return refinedRule;
}
