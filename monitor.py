"""Scapy packet capture and protocol analysis."""

from datetime import datetime, timezone
from typing import Any

from scapy.all import IP, ICMP, TCP, UDP, Packet, sniff

from database import init_db, insert_packet
from detector import PortScanDetector


def analyze_packet(packet: Packet) -> dict[str, Any] | None:
    if not packet.haslayer(IP):
        return None

    if packet.haslayer(TCP):
        protocol = "TCP"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        source_port = None
        destination_port = None
    else:
        return None

    return {
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_size": len(packet),
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


def process_packet(packet: Packet, detector: PortScanDetector | None = None) -> dict[str, Any] | None:
    analyzed = analyze_packet(packet)
    if analyzed is None:
        return None

    insert_packet(analyzed)
    if detector is not None:
        detector.inspect(analyzed)
    return analyzed


def start_capture(interface: str | None = None, detector: PortScanDetector | None = None) -> None:
    init_db()
    active_detector = detector or PortScanDetector()
    sniff(
        iface=interface,
        prn=lambda packet: process_packet(packet, active_detector),
        store=False,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Capture and analyze Linux network packets")
    parser.add_argument("-i", "--interface", help="Interface to monitor, for example eth0")
    args = parser.parse_args()
    start_capture(args.interface)
