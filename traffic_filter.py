from scapy.all import sniff

def packet_filter(packet):
    if packet.haslayer(IP):
        if packet[IP].src == "192.168.1.1" or packet[IP].dst == "192.168.1.1":
            print(f"Filtered Packet: {packet.summary()}")

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_filter, store=False)

if __name__ == "__main__":
    interface = "eth0"  # Change this to your network interface
    start_sniffing(interface)