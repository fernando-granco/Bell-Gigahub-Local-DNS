#!/usr/bin/env python3
"""
Bell Giga Hub - Local DNS Configuration Checker
A tool to connect to a Bell Giga Hub router and extract active DNS settings.
"""

import sys
import argparse
import getpass
from bell_gigahub_pihole_dns import GigahubAPI

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Diagnose DNS servers broadcasted and relayed by the Bell Giga Hub."
    )
    parser.add_argument(
        "-i", "--ip",
        default=None,
        help="IP address of the Bell Giga Hub gateway"
    )
    parser.add_argument(
        "-u", "--user",
        default="admin",
        help="Router administrator username (default: admin)"
    )
    return parser.parse_args()

def main():
    args = parse_arguments()

    print("=== Network Diagnosis: Bell Giga Hub ===")
    
    # Prompt for the Router IP first if not provided via arguments
    router_ip = args.ip
    if not router_ip:
        try:
            user_input = input("Enter the Router IP address [Default: 192.168.2.1] ").strip()
            # If the user presses Enter without typing, use the default Bell IP
            router_ip = user_input if user_input else "192.168.2.1"
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Operation cancelled by user.")
            sys.exit(0)

    if not router_ip:
        print("[-] Error: Router IP address cannot be empty.")
        sys.exit(1)

    # Prompt for the password securely
    try:
        password = getpass.getpass(f"Admin password for user '{args.user}': ")
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Operation cancelled by user.")
        sys.exit(0)

    if not password:
        print("[-] Error: Password cannot be empty.")
        sys.exit(1)

    # Initializing the API with provided settings
    api = GigahubAPI(router_ip, password)

    try:
        print("\n[+] Connecting and authenticating with the gateway at " + router_ip + "...")
        api.login()
        print("[+] Connection successful.")
    except Exception as exc:
        print(f"[-] Connection or authentication failed.")
        print(f"    Details: {type(exc).__name__}: {exc}")
        sys.exit(1)

    # Dictionary of standardized TR-181 paths to inspect
    dns_paths = {
        "DNS Servers broadcasted via DHCP (Pool 1)": "Device/DHCPv4/Server/Pools/Pool/DNSServers",
        "DNS Relay (Primary Server)"              : "Device/DNS/Relay/Forwardings/Forwarding/DNSServer",
        "DNS Relay (Secondary Server)"            : "Device/DNS/Relay/Forwardings/Forwarding/DNSServer",
    }

    print("\n=== Extracting DNS Configurations ===")
    has_errors = False

    for label, path in dns_paths.items():
        try:
            value = api.get_value(path)
            clean_value = value if value and value.strip() else "(Empty / Not configured)"
            print(f"* {label}:\n   {clean_value}")
        except Exception as exc:
            print(f"[X] {label}:\n   Unable to read value ({type(exc).__name__})")
            has_errors = True

    print("\n=========================================")
    if not has_errors:
        print("[+] Diagnosis completed successfully.")
    else:
        print("[!] Diagnosis completed with partial access errors.")

if __name__ == "__main__":
    main()
