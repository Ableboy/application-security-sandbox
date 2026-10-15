from scapy.all import sniff, IP, TCP, UDP

def packet_handler(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        print(f"[+] {src} → {dst} | Protocol: {proto}")

sniff(iface="lo", prn=packet_handler, count=10)