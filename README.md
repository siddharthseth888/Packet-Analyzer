
# Packet-Analyzer

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)

**Packet-Analyzer** is a Python-based network packet analyzer that leverages the **Scapy** library to capture and analyze live network traffic. It provides real-time insights into network protocols such as IP, TCP, UDP, ICMP, HTTP, and DNS. This project is intended for educational and controlled lab environments. Unauthorized packet capturing on networks without permission may be illegal.

---

## Features

- Live packet capture on specified network interfaces
- Protocol analysis for:
  - IPv4 & IPv6
  - TCP, UDP, ICMP
  - HTTP requests and responses
  - DNS queries and responses
- BPF (Berkeley Packet Filter) support (e.g., `tcp port 80`)
- Optional logging of captured packets to a file
- Display source/destination IPs, ports, timestamps, and protocol information

---

## Prerequisites

- Python 3.8 or higher
- Linux or WSL recommended for full packet capture functionality
- Root privileges to capture packets on network interfaces
- Git

---

## Installation

1. **Clone the repository**

```bash
git clone git@github.com:siddharthseth888/Packet-Analyzer.git
cd Packet-Analyzer
```

2. **Set up a Python virtual environment**

```bash
python3 -m venv .venv
```

3. **Activate the virtual environment**
  For Linux and MacOS
```bash
source .venv/bin/activate
```
  For Windows(Powershell)
```bash
.venv\Scripts\Activate
```

4. **Upgrade pip and install dependencies**

```bash
pip install --upgrade pip
pip install scapy
```

5. **Verify Installation**

```bash
python3 -c "from scapy.all import *; print('Scapy installed successfully!')"
```
If no errors are shown, you are ready to run the analyzer.

## Running the Packet Analyzer
**Running the Main Script**

```bash
python3 packet_analyzer.py
```

## Usage Guide

```bash
# Basic usage
sudo python3 packet_analyzer.py -i eth0

# With a filter (only TCP 80 traffic)
sudo python3 packet_analyzer.py -i eth0 -f "tcp port 80"

# Capture only 100 packets
sudo python3 packet_analyzer.py -i eth0 -c 100

# Save output to log file
sudo python3 packet_analyzer.py -i eth0 -l output.log
```

Thanks For Reading!
Keep coding!

🔗 [LinkedIn Profile](https://www.linkedin.com/in/siddharth-seth-3448ab255/)
