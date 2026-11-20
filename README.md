# Linux Network Monitoring & Intrusion Detection System

A small Linux IDS demonstration built with Python, Scapy, Flask, and SQLite.

## Run on Ubuntu

```bash
sudo apt update
sudo apt install python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python demo.py
python app.py
```

Open `http://127.0.0.1:5000`. The demo writes three normal packets and eight TCP connections to different ports from `10.0.10.20`, which creates one `Port Scan Detected` alert.

For live capture, run the monitor with root privileges in another terminal:

```bash
sudo .venv/bin/python monitor.py --interface eth0
```

Replace `eth0` with the interface attached to the VirtualBox lab network. The detector watches TCP traffic from one source to one destination and raises a HIGH alert when it sees eight different destination ports within ten seconds. Alerts are deduplicated for the lifetime of the monitor process.

## Database tables

- `packets`: source/destination addresses, protocol, ports, size, and timestamp.
- `alerts`: alert type, severity, description, source/destination, and timestamp.
