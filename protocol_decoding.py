from scapy.all import sniff, HTTPRequest, HTTPResponse

def packet_callback(packet):
    if packet.haslayer(HTTPRequest):
        print(f"HTTP Request: {packet[HTTPRequest].Host}{packet[HTTPRequest].Path}")
    if packet.haslayer(HTTPResponse):
        print(f"HTTP Response: {packet[HTTPResponse].Status_Code}")

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    interface = "eth0"  # Change this to your network interface
    start_sniffing(interface)