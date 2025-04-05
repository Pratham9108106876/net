from scapy.all import *
from collections import Counter

traffic_counter = Counter()

def packet_callback(packet):
    if packet.haslayer(IP):
        traffic_counter[packet[IP].proto] += 1
        print(f"IP Packet: {packet[IP].src} -> {packet[IP].dst}")
    if packet.haslayer(TCP):
        traffic_counter['TCP'] += 1
        print(f"TCP Packet: {packet[TCP].sport} -> {packet[TCP].dport}")
    if packet.haslayer(UDP):
        traffic_counter['UDP'] += 1
        print(f"UDP Packet: {packet[UDP].sport} -> {packet[UDP].dport}")
    if packet.haslayer(HTTPRequest):
        traffic_counter['HTTP'] += 1
        print(f"HTTP Request: {packet[HTTPRequest].Host}{packet[HTTPRequest].Path}")
    if packet.haslayer(HTTPResponse):
        traffic_counter['HTTP'] += 1
        print(f"HTTP Response: {packet[HTTPResponse].Status_Code}")

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    interface = "eth0"  # Change this to your network interface
    start_sniffing(interface)
    print("Traffic Summary:", traffic_counter)