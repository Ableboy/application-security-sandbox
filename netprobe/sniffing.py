# USING Scapy to work directly with raw packets at the network layer
from scapy.all import sniff, IP, TCP, UDP

# Translate IP protocol numbers into human-readable names
PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP"}

# This function runs automatically every time a packet is captured
def packet_handler(packet):
    
    # Only process packets that have an IP layer — not all packets do
    if IP in packet:
        
        # Read source and destination IP from the IP header (Layer 3)
        src = packet[IP].src
        dst = packet[IP].dst
        
        # Read protocol number from IP header, then translate it
        proto_num = packet[IP].proto
        proto_name = PROTOCOLS.get(proto_num, str(proto_num))
        
        # Print a clean summary line for each packet
        print(f"[+] {src} -> {dst} | Protocol: {proto_name}")

# Start capturing 10 packets on loopback interface
# prn= means: call packet_handler for every packet captured
sniff(iface="lo", prn=packet_handler, count=10)
