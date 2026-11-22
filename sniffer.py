from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from datetime import datetime
import socket
import csv

CSV_FILENAME = "traffic_logs.csv"

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit/Shell", 5432: "PostgreSQL", 8080: "HTTP-Proxy"
}

TCP_FLAGS_MAP = {
    "S": "SYN",
    "SA": "SYN-ACK",
    "A": "ACK",
    "PA": "PSH-ACK",
    "FA": "FIN-ACK",
    "F": "FIN",
    "R": "RST",
    "RA": "RST-ACK"
}


def get_local_ip():
    """Detect the active local network IP address of this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()


def get_direction(src_ip, dst_ip):
    """Classify traffic as Incoming, Outgoing, or Internal."""
    if src_ip == LOCAL_IP and dst_ip == LOCAL_IP:
        return "Local"
    elif src_ip == LOCAL_IP:
        return "Outgoing"
    elif dst_ip == LOCAL_IP:
        return "Incoming"
    return "Internal"


def identify_service(sport, dport):
    """Map well-known port numbers to service names."""
    if dport in COMMON_PORTS:
        return COMMON_PORTS[dport]
    if sport in COMMON_PORTS:
        return COMMON_PORTS[sport]
    return "Other"


def process_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    size = len(packet)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    direction = get_direction(src_ip, dst_ip)

    src_port = 0
    dst_port = 0
    protocol = "Other"
    info = "IP Packet"

    if packet.haslayer(DNS):
        protocol = "DNS"
        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        info = "DNS Query/Response"
    elif TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        raw_flags = str(packet[TCP].flags)
        flag_desc = TCP_FLAGS_MAP.get(raw_flags, raw_flags)
        service = identify_service(src_port, dst_port)
        info = f"{service} | {flag_desc}"
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        service = identify_service(src_port, dst_port)
        info = f"{service} Datagram"
    elif ICMP in packet:
        protocol = "ICMP"
        info = f"ICMP Type {packet[ICMP].type}"

    print(
        f"[{direction:8}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
        f"| {protocol:4} | {size:4} B | {info}"
    )

    with open(CSV_FILENAME, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, direction, size, info
        ])


def main():
    print("==========================================================")
    print("        NETWORK TRAFFIC ANALYZER - PACKET SNIFFER         ")
    print("==========================================================")
    print(f"[*] Detected Local Host IP : {LOCAL_IP}")

    user_input = input("[?] Enter packet count to capture (Default = 100, 0 = Continuous): ").strip()
    if user_input == "":
        packet_count = 100
    else:
        try:
            packet_count = int(user_input)
        except ValueError:
            print("[!] Invalid number entered. Falling back to 100 packets.")
            packet_count = 100

    with open(CSV_FILENAME, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Timestamp", "Source IP", "Destination IP",
            "Source Port", "Destination Port", "Protocol",
            "Direction", "Size", "Info"
        ])

    if packet_count == 0:
        print("[*] Starting continuous capture... Press Ctrl+C to stop.\n")
        try:
            sniff(prn=process_packet, store=False)
        except KeyboardInterrupt:
            print("\n[*] Capture stopped by user.")
    else:
        print(f"[*] Capturing {packet_count} packets... Generate some browser/network traffic.\n")
        sniff(prn=process_packet, count=packet_count, store=False)

    print(f"\n[*] Capture complete. Data saved to '{CSV_FILENAME}'.")


if __name__ == "__main__":
    main()