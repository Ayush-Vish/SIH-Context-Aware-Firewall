import subprocess
import sys
import re
import os
from typing import List, Set, Dict

class FirewallAgent:
    def __init__(self):
        self.PORT_PROTOCOL_MAP = {
            80: "HTTP", 443: "HTTPS", 53: "DNS",
            21: "FTP", 22: "SSH", 25: "SMTP",
            110: "POP3", 143: "IMAP"
        }
        self.rules = []

    def execute_command(self, command, success_message="Command executed successfully."):
        """Helper function to execute subprocess commands."""
        try:
            print("Executing command:", command)
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                print(success_message)
                print(result.stdout.strip())
                return {"success": True, "message": result.stdout.strip(), "data": result.stdout.strip()}
            else:
                print("An error occurred:")
                return {"success": False, "message": result.stderr.strip()}
        except Exception as e:
            print(f"Failed to execute command: {e}")
            return {"success": False, "message": str(e)}

    def block_ips_addresses(self, domains: List[str] = [], ips: List[str] = [], should_block: bool = True) -> Dict[str, any]:
        """
        Block or unblock specified domains and IPs

        Args:
            domains: List of domains to block/unblock
            ips: List of IP addresses to block/unblock
            should_block: True to block, False to unblock

        Returns:
            Dict containing status and results
        """
        results = {
            "success": True,
            "blocked_ips": set(),
            "failed_ips": set(),
            "blocked_domains": set(),
            "failed_domains": set(),
            "errors": []
        }

        if not os.geteuid() == 0:
            results["success"] = False
            results["errors"].append("Script must be run as root (sudo)")
            return results

        def is_valid_ip(ip: str) -> bool:
            pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if not re.match(pattern, ip):
                return False
            octets = ip.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)

        def is_valid_domain(domain: str) -> bool:
            return bool(re.match(r'^(www\.)?[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', domain))

        def resolve_domain(domain: str) -> Set[str]:
            try:
                clean_domain = domain.replace('www.', '')
                cmd = f"dig +short {clean_domain} A"
                result = subprocess.check_output(cmd, shell=True).decode('utf-8')
                ips = {ip.strip() for ip in result.split('\n') if ip.strip()}

                cmd_www = f"dig +short www.{clean_domain} A"
                result_www = subprocess.check_output(cmd_www, shell=True).decode('utf-8')
                ips.update({ip.strip() for ip in result_www.split('\n') if ip.strip()})

                return ips
            except subprocess.CalledProcessError:
                return set()

        def manage_hosts_file(domain: str, remove: bool = False) -> bool:
            clean_domain = domain.replace('www.', '')
            try:
                if not remove:
                    entries = [
                        f"127.0.0.1 {clean_domain}",
                        f"127.0.0.1 *.{clean_domain}",
                        f"127.0.0.1 www.{clean_domain}"
                    ]
                    with open('/etc/hosts', 'a') as f:
                        f.write('\n' + '\n'.join(entries) + '\n')
                else:
                    with open('/etc/hosts', 'r') as f:
                        lines = f.readlines()
                    new_lines = [line for line in lines if clean_domain not in line]
                    with open('/etc/hosts', 'w') as f:
                        f.writelines(new_lines)
                return True
            except PermissionError:
                results["errors"].append(f"Permission error modifying hosts file for {domain}")
                return False

        def manage_ip(ip: str, block: bool = True) -> bool:
            action = '-A' if block else '-D'
            try:
                subprocess.run(['iptables', action, 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                subprocess.run(['iptables', action, 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True)
                return True
            except subprocess.CalledProcessError:
                return False

        # Process IPs
        for ip in ips:
            if is_valid_ip(ip):
                if manage_ip(ip, should_block):
                    results["blocked_ips"].add(ip)
                else:
                    results["failed_ips"].add(ip)
                    results["success"] = False
            else:
                results["failed_ips"].add(ip)
                results["errors"].append(f"Invalid IP format: {ip}")
                results["success"] = False

        # Process Domains
        for domain in domains:
            if is_valid_domain(domain):
                domain_ips = resolve_domain(domain)
                if domain_ips:
                    manage_hosts_file(domain, not should_block)
                    for ip in domain_ips:
                        if manage_ip(ip, should_block):
                            results["blocked_ips"].add(ip)
                        else:
                            results["failed_ips"].add(ip)
                            results["success"] = False
                    results["blocked_domains"].add(domain)
                else:
                    results["failed_domains"].add(domain)
                    results["errors"].append(f"Could not resolve domain: {domain}")
                    results["success"] = False
            else:
                results["failed_domains"].add(domain)
                results["errors"].append(f"Invalid domain format: {domain}")
                results["success"] = False

        # Flush DNS cache
        try:
            commands = [
                ['systemctl', 'restart', 'systemd-resolved'],
                ['service', 'network-manager', 'restart'],
                ['resolvectl', 'flush-caches'],
                ['systemd-resolve', '--flush-caches']
            ]
            for cmd in commands:
                try:
                    subprocess.run(cmd, check=True)
                    break
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
        except Exception as e:
            results["errors"].append(f"Failed to flush DNS cache: {str(e)}")

        # Convert sets to lists for better JSON serialization
        results["blocked_ips"] = list(results["blocked_ips"])
        results["failed_ips"] = list(results["failed_ips"])
        results["blocked_domains"] = list(results["blocked_domains"])
        results["failed_domains"] = list(results["failed_domains"])

        return results

fire = FirewallAgent()