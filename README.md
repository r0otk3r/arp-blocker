#  ARP-Based Network Blocker

> A simple yet powerful ARP spoofing tool to block devices on your local network.

**Author:** r0otk3r  
**License:** MIT  
**Language:** Python 3  
**Platform:** Linux (Kali, Debian, etc.)

---

## Description

This script allows you to:

- Scan and list devices on your LAN.
- Block a specific IP using continuous ARP spoofing.
- Block all IPs except the gateway (mass-blocking).
- Use a specified network interface.
- Automatically resolve hostnames of devices.

ARP spoofing is used to poison the ARP table of target devices and redirect traffic.

---

## ⚙️ Features

- Scan your network and list live devices  
- Block a single target by IP address  
- Block **all devices** except the gateway  
- Real-time spoofing with configurable duration  
- Hostname resolution  
- Requires no external tools except `scapy` and `netifaces`

---

## Requirements

- Python 3.x
- `scapy`
- `netifaces`

Install dependencies:

```bash
pip install scapy netifaces
```
## Usage
```bash
sudo python3 network_blocker.py -i <interface> [options]
```
#### Arguments
| Option            | Description                                     |
| ----------------- | ----------------------------------------------- |
| `-i, --interface` | Network interface to use (e.g. `eth0`, `wlan0`) |
| `-t, --target`    | Target IP to block                              |
| `-d, --duration`  | Spoofing duration in seconds (default: 10)      |
| `--list`          | List devices on the LAN                         |
| `--block-all`     | Block all devices except gateway                |


## Examples

#### List all devices on the network
```bash
sudo python3 network_blocker.py -i wlan0 --list
```
#### Block a single target
```bash
sudo python3 network_blocker.py -i wlan0 -t 192.168.1.50 -d 15
```
#### Block all devices except the gateway
```bash
sudo python3 network_blocker.py -i wlan0 --block-all -d 30
```

<img width="1349" height="621" alt="network" src="https://github.com/user-attachments/assets/c64ab602-19b1-43c6-b1d5-2d21583e44da" />

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only.
Do NOT use this on networks you do not own or have explicit permission to test.



## Official Channels

- [YouTube @rootctf](https://www.youtube.com/@rootctf)
- [X @r0otk3r](https://x.com/r0otk3r)
