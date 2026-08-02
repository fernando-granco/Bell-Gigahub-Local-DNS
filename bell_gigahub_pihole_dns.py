#!/usr/bin/env python3
"""
Bell Gigahub - Force a local DNS server on your LAN
===================================================
This script points the Bell Gigahub at a DNS server running on your own
network, such as Pi-hole, AdGuard Home or unbound.

The Gigahub GUI does NOT allow you to change the DNS server for LAN devices.
This script skips the GUI and talks directly to the router's API.

Requirements:
  - Python 3.6+ (no extra packages needed)
  - Your Bell Gigahub admin password (on the modem sticker)
  - Your DNS server running and reachable on your LAN

Usage:
  python bell_gigahub_pihole_dns.py

You'll be prompted for:
  1. Router IP (default: 192.168.2.1)
  2. Admin password (from modem sticker)
  3. Which method to use: DHCP or forwarding
  4. The DNS server address clients should use

https://github.com/fernando-granco/Bell-Gigahub-Local-DNS
"""

import hashlib
import ipaddress
import json
import urllib.request
import urllib.parse
import random
import socket
import struct
import sys
import time


# ─── Configuration ───────────────────────────────────────────────

def get_connection():
    """Ask only what is needed to log in."""
    print("Bell Gigahub Local DNS")
    print("-" * 50)

    router_ip = input("Router IP [192.168.2.1]: ").strip() or "192.168.2.1"

    password = input("Admin password: ").strip()
    if not password:
        print("ERROR: Password is required.", file=sys.stderr)
        sys.exit(1)

    return router_ip, password


def choose_method(risk):
    """Ask how clients should be pointed at the DNS server."""
    compatible = risk not in ("known", "suspected")

    print()
    print("How should your devices reach your DNS server?")
    print("  1) DHCP     - devices are told to use it directly  (recommended)")
    print("  2) Forward  - the router passes each lookup along to it")
    if not compatible:
        print("                NOT COMPATIBLE with this Gigahub's firmware")
    elif risk == "unknown":
        print("                untested on this firmware, it may not work")

    method = "relay" if input("Choice [1]: ").strip() == "2" else "dhcp"

    print()
    if method == "dhcp":
        print("  Your devices will be told to use your DNS server directly.")
        print("  They pick this up when their network lease renews, or after")
        print("  a reboot.")
    else:
        print("  The router keeps answering your devices, and passes each")
        print("  lookup along to your DNS server. This applies right away,")
        print("  but your DNS server sees every request as coming from the")
        print("  router rather than from the device that asked.")
        if not compatible:
            print()
            print("  On this firmware that usually knocks your DNS server off")
            print("  the network, which takes the whole LAN's DNS down with it.")
            print("  Everything is put back automatically if that happens.")
            if input("  Try it anyway? [y/N]: ").strip().lower() not in ("y", "yes"):
                print("\nAborted. Nothing was changed.")
                sys.exit(0)

    return method


def get_dns_servers():
    """Ask which DNS server clients should use."""
    print()
    dns1 = input("DNS server IP [192.168.2.10]: ").strip() or "192.168.2.10"
    dns2 = input("Secondary [same as above]: ").strip() or dns1
    return dns1, dns2


# ─── Firmware behaviour ─────────────────────────────────────────

# On some Gigahub firmware, pointing the DNS relay at a LAN address makes the
# router blackhole that host at the IP layer: it keeps answering ARP, and other
# LAN devices can still reach it, but the router drops every routed packet from
# it, including packets addressed to the router itself. The DNS server you just
# pointed at can then no longer reach its own upstreams, so it stops answering
# and LAN-wide DNS goes down with it.
#
# Measured on two units with identical HardwareVersion 5690-000001-000, both
# tested 2026-08-01:
#
#   2.14.2     blackholes the relay target
#   3.11.6.2   works normally
#
# So the fault is in the older firmware and appears to be fixed in 3.x. If your
# Gigahub is on 2.x, updating it may be the real solution.
#
# These lists are a courtesy warning only. Firmware we have never seen may
# behave either way, so the real protection is the probe-and-roll-back check
# after writing, which tests behaviour rather than version numbers.
AFFECTED_SOFTWARE_VERSIONS = {"2.14.2"}
KNOWN_GOOD_SOFTWARE_VERSIONS = {"3.11.6.2"}

# The only model either version was tried on.
TESTED_MODELS = {"5690"}


def is_tested(model, software):
    """True if this exact model and firmware have actually been tried."""
    return model in TESTED_MODELS and software in (
        AFFECTED_SOFTWARE_VERSIONS | KNOWN_GOOD_SOFTWARE_VERSIONS
    )


def relay_risk(software):
    """How likely the relay method is to cut off the target on this firmware.

    Returns "known", "suspected", "none" or "unknown".
    """
    if software in AFFECTED_SOFTWARE_VERSIONS:
        return "known"
    if software in KNOWN_GOOD_SOFTWARE_VERSIONS:
        return "none"
    # Only 2.x has ever been seen doing this, and 3.x has been seen not to.
    if str(software).split(".")[0] == "2":
        return "suspected"
    return "unknown"


def is_private_ipv4(address):
    """True if this address is on a LAN, i.e. exposed to the blackhole bug."""
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def dns_probe(server, timeout=3.0):
    """True if `server` can actually resolve a name, not merely reply.

    "Something answered on port 53" is not good enough. A server the router has
    cut off still answers its LAN neighbours perfectly well; what it can no
    longer do is reach its own upstreams. So ask for a random name under a real
    domain. It cannot be served from cache, and only a working resolver chain
    can return NOERROR or NXDOMAIN for it. SERVFAIL, REFUSED and silence all
    mean the server is not resolving, whatever else it may be doing.
    """
    query_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    name = "probe%d.google.com" % random.randint(100000, 999999)
    qname = b"".join(
        bytes([len(label)]) + label.encode() for label in name.split(".")
    ) + b"\x00"
    packet = header + qname + struct.pack(">HH", 1, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        reply, _ = sock.recvfrom(512)
    except (socket.timeout, OSError):
        return False
    finally:
        sock.close()

    if len(reply) < 4 or reply[:2] != packet[:2]:
        return False
    rcode = struct.unpack(">H", reply[2:4])[0] & 0x0F
    return rcode in (0, 3)  # NOERROR or NXDOMAIN; both prove it resolved


def confirm(prompt):
    """Ask the user to type yes. Anything else aborts."""
    return input(f"{prompt} [type 'yes' to continue]: ").strip().lower() == "yes"


# ─── Router status codes ────────────────────────────────────────

# The Gigahub reports success as XMO_NO_ERR for an action and
# XMO_REQUEST_NO_ERR for the request as a whole. The number behind those names
# is not stable across firmware builds: 16777239 and 16777238 have both been
# seen meaning XMO_NO_ERR on FAST 5689E units. Match on the name, which is
# stable, so an unseen firmware build works too. Genuine failures are named
# XMO_UNKNOWN_PATH_ERR, XMO_AUTHENTICATION_ERR and so on, none of which end in
# NO_ERR, so this cannot mistake an error for success.
NO_ERR_SUFFIX = "NO_ERR"

# Used only when a firmware sends no description at all.
NO_ERR_CODES = (16777238, 16777239)


def check_ok(action, what):
    """Raise unless the router reported success for this action."""
    error = action["error"]
    description = error.get("description", "")

    if description.endswith(NO_ERR_SUFFIX):
        return
    if not description and error.get("code") in NO_ERR_CODES:
        return

    raise RuntimeError(
        f"{what} failed: {description or 'unknown error'} "
        f"(code {error.get('code')})"
    )


# ─── Gigahub API Client ─────────────────────────────────────────

class GigahubAPI:
    """Client for the Bell Gigahub JSON-RPC API."""

    def __init__(self, router_ip, password):
        self.base_url = f"http://{router_ip}"
        self.user = "admin"
        self.hash_encoder_pass = hashlib.sha512(
            password.encode()
        ).hexdigest()
        self.session_id = None
        self.nonce = None
        self.ha1 = None
        self.req_index = 0

        self.headers = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json, text/javascript, */*; q=0.01"),
            ("X-Requested-With", "XMLHttpRequest"),
            ("User-Agent", "Mozilla/5.0"),
        ]

    def _compute_auth_key(self, req_id, cnonce):
        """Compute the auth-key for request authentication."""
        auth_str = f"{self.ha1}:{req_id}:{cnonce}:JSON:/cgi/json-req"
        return hashlib.sha512(auth_str.encode()).hexdigest()

    def _send(self, actions):
        """Send a request to the Gigahub JSON-RPC endpoint."""
        cnonce = str(random.randint(0, 4294967295))
        req_id = self.req_index
        self.req_index += 1
        auth_key = self._compute_auth_key(req_id, cnonce)

        body = {
            "request": {
                "id": req_id,
                "session-id": self.session_id or "0",
                "priority": False,
                "cnonce": cnonce,
                "auth-key": auth_key,
                "actions": actions,
            }
        }

        json_str = json.dumps(body, separators=(",", ":"))
        data = urllib.parse.urlencode({"req": json_str}).encode()

        req = urllib.request.Request(
            f"{self.base_url}/cgi/json-req",
            data=data,
            method="POST",
        )
        for name, value in self.headers:
            req.add_header(name, value)

        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())

    def login(self):
        """Authenticate with the router."""
        ha1_initial = hashlib.sha512(
            f"{self.user}::{self.hash_encoder_pass}".encode()
        ).hexdigest()

        cnonce = str(random.randint(0, 4294967295))
        auth_key = hashlib.sha512(
            f"{ha1_initial}:0:{cnonce}:JSON:/cgi/json-req".encode()
        ).hexdigest()

        body = {
            "request": {
                "id": 0,
                "session-id": "0",
                "priority": False,
                "cnonce": cnonce,
                "auth-key": auth_key,
                "actions": [
                    {
                        "id": 0,
                        "method": "logIn",
                        "parameters": {
                            "user": self.user,
                            "persistent": "true",
                            "session-options": {
                                "nss": [
                                    {
                                        "name": "gtw",
                                        "uri": "http://sagemcom.com/gateway-data",
                                    }
                                ],
                                "context-flags": {
                                    "get-content-name": True,
                                    "local-time": True,
                                },
                                "capability-depth": 2,
                                "capability-flags": {
                                    "name": True,
                                    "default-value": False,
                                    "restriction": True,
                                    "description": False,
                                },
                                "time-format": "ISO_8601",
                            },
                        },
                    }
                ],
            }
        }

        json_str = json.dumps(body, separators=(",", ":"))
        data = urllib.parse.urlencode({"req": json_str}).encode()

        req = urllib.request.Request(
            f"{self.base_url}/cgi/json-req",
            data=data,
            method="POST",
        )
        for name, value in self.headers:
            req.add_header(name, value)

        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())

        action = result["reply"]["actions"][0]
        check_ok(action, "Login")

        self.session_id = str(
            action["callbacks"][0]["parameters"]["id"]
        )
        self.nonce = action["callbacks"][0]["parameters"]["nonce"]
        self.ha1 = hashlib.sha512(
            f"{self.user}:{self.nonce}:{self.hash_encoder_pass}".encode()
        ).hexdigest()
        self.req_index = 1

    def get_value(self, xpath):
        """Get a value from the router configuration."""
        opts = {
            "nss": [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}],
            "context-flags": {"get-content-name": True, "local-time": True},
            "capability-depth": 3,
            "capability-flags": {
                "name": True,
                "default-value": True,
                "restriction": True,
                "description": True,
            },
            "time-format": "ISO_8601",
        }

        result = self._send(
            [
                {
                    "id": 0,
                    "method": "getValue",
                    "xpath": xpath,
                    "options": opts,
                }
            ]
        )

        action = result["reply"]["actions"][0]
        check_ok(action, "getValue")

        return action["callbacks"][0]["parameters"]["value"]

    def set_value(self, xpath, value):
        """Set a value in the router configuration."""
        opts = {
            "nss": [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}],
            "context-flags": {"get-content-name": True, "local-time": True},
            "capability-depth": 3,
            "capability-flags": {
                "name": True,
                "default-value": True,
                "restriction": True,
                "description": True,
            },
            "time-format": "ISO_8601",
        }

        result = self._send(
            [
                {
                    "id": 0,
                    "method": "setValue",
                    "xpath": xpath,
                    "parameters": {"value": value},
                    "options": opts,
                }
            ]
        )

        action = result["reply"]["actions"][0]
        check_ok(action, "setValue")

    def get_device_info(self):
        """Return the router's identity, for the firmware warning."""
        try:
            return self.get_value("Device/DeviceInfo")["DeviceInfo"]
        except Exception:
            return {}




# ─── Applying the change ────────────────────────────────────────

DHCP_DNS_XPATH = "Device/DHCPv4/Server/Pools/Pool[1]/DNSServers"
RELAY_XPATH = "Device/DNS/Relay/Forwardings/Forwarding[{}]/DNSServer"


def read_current(api, method):
    """Return {xpath: value} for whatever this method is about to overwrite."""
    current = {}
    if method == "dhcp":
        try:
            current[DHCP_DNS_XPATH] = api.get_value(DHCP_DNS_XPATH)
        except Exception:
            pass
    else:
        for slot in (1, 2):
            xpath = RELAY_XPATH.format(slot)
            try:
                current[xpath] = api.get_value(xpath)
            except Exception:
                pass
        # Writing the relay also rewrites what DHCP advertises, so capture that
        # too or a rollback would silently discard the user's DHCP setting.
        # Restored last, because putting the relay back moves it again.
        try:
            current[DHCP_DNS_XPATH] = api.get_value(DHCP_DNS_XPATH)
        except Exception:
            pass
    return current


def apply_change(api, method, dns1, dns2):
    """Write the new setting and return {label: value} of what was verified."""
    if method == "dhcp":
        # One entry only. A public secondary here would let clients bypass the
        # Pi-hole whenever it is slow to answer.
        servers = dns1 if dns1 == dns2 else f"{dns1},{dns2}"
        api.set_value(DHCP_DNS_XPATH, servers)
        print(f"  DHCP DNS servers -> {servers}")
        return {"DHCP DNS servers": api.get_value(DHCP_DNS_XPATH)}

    api.set_value(RELAY_XPATH.format(1), dns1)
    print(f"  DNS relay #1 -> {dns1}")
    api.set_value(RELAY_XPATH.format(2), dns2)
    print(f"  DNS relay #2 -> {dns2}")
    return {
        "DNS relay #1": api.get_value(RELAY_XPATH.format(1)),
        "DNS relay #2": api.get_value(RELAY_XPATH.format(2)),
    }


def roll_back(api, original):
    """Put back everything we overwrote."""
    for xpath, value in original.items():
        try:
            api.set_value(xpath, value)
            print(f"    restored {xpath.split('/')[-1]} = {value}")
        except Exception as exc:
            print(f"    FAILED to restore {xpath}: {exc}", file=sys.stderr)


# ─── Main ───────────────────────────────────────────────────────

def main():
    router_ip, password = get_connection()
    api = GigahubAPI(router_ip, password)

    print()
    print("Connecting...")
    try:
        api.login()
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        print("  Check that the router IP and admin password are correct.", file=sys.stderr)
        sys.exit(1)

    info = api.get_device_info()
    model = info.get("ModelName", "?")
    software = info.get("SoftwareVersion", "unknown")
    print(f"  Gigahub {model}, firmware {software}")

    if not is_tested(model, software):
        print("  This model and firmware have not been tested.")
        print("  The script may not work correctly here.")

    # The cut-off is triggered by the relay setting only. Advertising the same
    # address over DHCP has been verified not to trigger it, because the router
    # never makes that host its own upstream resolver.
    risk = relay_risk(software)
    method = choose_method(risk)

    dns1, dns2 = get_dns_servers()
    targets_lan = is_private_ipv4(dns1) or is_private_ipv4(dns2)

    # Read what we are about to overwrite, so we can undo it.
    print()
    print("Reading current settings...")
    original = read_current(api, method)
    for xpath, value in original.items():
        print(f"  Current {xpath.split('/')[-1]}: {value}")

    # Make sure the target answers before we send the whole LAN to it.
    if targets_lan:
        print()
        print("Checking the DNS server responds before pointing the router at it...")
        if dns_probe(dns1):
            print(f"  {dns1} is answering on port 53.")
        else:
            print(f"  WARNING: {dns1} is not answering on port 53.")
            print("  Pointing the router at a server that cannot answer will")
            print("  take DNS down for every device on the LAN.")
            if not confirm("Continue anyway?"):
                print("Aborted. Nothing was changed.")
                sys.exit(0)

    print()
    print("Applying changes...")
    verified = apply_change(api, method, dns1, dns2)

    print()
    print("Verifying changes...")
    for label, value in verified.items():
        print(f"  {label}: {value}")

    # Storing the value is not enough. On affected firmware the router accepts
    # it and then cuts the host off, so check the behaviour, not the setting.
    if targets_lan and original:
        print()
        print("Checking the DNS server still works now that it is the target...")
        time.sleep(6)

        if dns_probe(dns1, timeout=4.0) or dns_probe(dns1, timeout=4.0):
            print(f"  {dns1} is still answering. Change looks good.")
        else:
            print(f"  {dns1} has STOPPED answering since the change.")
            print("  Rolling back so you do not lose DNS...")
            roll_back(api, original)
            print()
            print("=" * 50)
            print("ROLLED BACK. Your DNS settings are as they were.")
            print()
            print(f"This Gigahub (firmware {software}) cuts off a LAN host once")
            print("it becomes the DNS target.")
            if method == "relay":
                print("Try again and choose method 1 (DHCP), which avoids this.")
            else:
                print("See the README for alternatives.")
            print("=" * 50)
            sys.exit(1)

    print()
    print("=" * 50)
    print("CONFIGURATION COMPLETE!")
    print()
    print("What was changed:")
    for label, value in verified.items():
        print(f"  {label} -> {value}")

    if method == "dhcp":
        print()
        print("Clients keep their old DNS until their DHCP lease renews.")
        print("To apply now:")
        print("  Windows:   ipconfig /renew")
        print("  Mac/Linux: renew the DHCP lease or toggle Wi-Fi off/on")
        print("  Or reboot the device")
    else:
        print()
        print("Clients query the router, so this takes effect immediately.")
        print("Your DNS server sees every query as coming from the router, so")
        print("per-client statistics will not work with this method.")

    print("=" * 50)


if __name__ == "__main__":
    main()
