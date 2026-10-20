import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):
    # Check if the packet contains an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Map protocol numbers
        protocol_name = "Other"
        if proto == 1:
            protocol_name = "ICMP"
        elif proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"

        print(f"\n[+] Packet Captured:")
        print(f"    ├── Source IP      : {src_ip}")
        print(f"    ├── Destination IP : {dst_ip}")
        print(f"    └── Protocol       : {protocol_name}")

        # Extract payload data if raw bytes exist
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    └── Payload Preview: {payload[:40]}")

def start_sniffer():
    print("=" * 60)
    print("         CodeAlpha - Basic Network Packet Sniffer           ")
    print("=" * 60)
    print("[-] Listening for network traffic... (Press Ctrl+C to stop)\n")
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[-] Sniffer stopped gracefully.")
    except PermissionError:
        print("[!] Error: You must run this script with Root/Administrator privileges!")

if __name__ == "__main__":
    start_sniffer()
