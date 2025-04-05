from scapy.all import sniff, PcapWriter
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse

def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"IP Packet: {packet[IP].src} -> {packet[IP].dst}")
    if packet.haslayer(TCP):
        print(f"TCP Packet: {packet[TCP].sport} -> {packet[TCP].dport}")
    if packet.haslayer(UDP):
        print(f"UDP Packet: {packet[UDP].sport} -> {packet[UDP].dport}")
    if packet.haslayer(HTTPRequest):
        print(f"HTTP Request: {packet[HTTPRequest].Host}{packet[HTTPRequest].Path}")
    if packet.haslayer(HTTPResponse):
        print(f"HTTP Response: {packet[HTTPResponse].Status_Code}")

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    interface = "eth0"  # Change this to your network interface
    start_sniffing(interface)