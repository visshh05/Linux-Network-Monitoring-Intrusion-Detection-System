"""Create normal traffic and a synthetic port scan for a classroom demonstration."""

from scapy.all import ICMP, IP, TCP, UDP

from database import init_db
from detector import PortScanDetector
from monitor import process_packet


def main() -> None:
    init_db()
    detector = PortScanDetector()
    normal_packets = [
        IP(src="10.0.10.10", dst="10.0.10.1") / ICMP(),
        IP(src="10.0.10.11", dst="10.0.10.1") / UDP(sport=53000, dport=53),
        IP(src="10.0.10.12", dst="10.0.10.1") / TCP(sport=41000, dport=443),
    ]
    scan_ports = [21, 22, 23, 25, 53, 80, 443, 8080]
    scan_packets = [
        IP(src="10.0.10.20", dst="10.0.10.1") / TCP(sport=45000 + index, dport=port, flags="S")
        for index, port in enumerate(scan_ports)
    ]

    for packet in normal_packets + scan_packets:
        process_packet(packet, detector)
    print("Demo complete: normal traffic stored and port scan alert generated.")
    print("Run: python app.py, then open http://127.0.0.1:5000")


if __name__ == "__main__":
    main()
