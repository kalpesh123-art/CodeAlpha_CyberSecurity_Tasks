from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

ip_tracker = defaultdict(list)
THRESHOLD = 15  # Alert if >15 SYN packets within 5 seconds
TIME_WINDOW = 5.0

def detect_intrusion(packet):
    if IP in packet and TCP in packet:
        if packet[TCP].flags == 'S':  # SYN Flag
            src_ip = packet[IP].src
            current_time = time.time()
            
            ip_tracker[src_ip].append(current_time)
            ip_tracker[src_ip] = [t for t in ip_tracker[src_ip] if current_time - t <= TIME_WINDOW]
            
            if len(ip_tracker[src_ip]) > THRESHOLD:
                print(f"🚨 [ALERT] Potential Port Scan/SYN Flood detected from IP: {src_ip}!")
                print(f"   └── {len(ip_tracker[src_ip])} SYN requests within {TIME_WINDOW} seconds.\n")

def run_nids():
    print("=" * 60)
    print("       CodeAlpha - Network Intrusion Detection System (NIDS)  ")
    print("=" * 60)
    print("[-] NIDS engine active. Monitoring network...\n")
    try:
        sniff(prn=detect_intrusion, store=False)
    except PermissionError:
        print("[!] Error: Administrator/Root privileges required.")

if __name__ == "__main__":
    run_nids()
