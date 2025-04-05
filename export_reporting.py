from scapy.all import sniff, wrpcap

packets = []

def packet_callback(packet):
    packets.append(packet)

def start_sniffing(interface, output_file):
    sniff(iface=interface, prn=packet_callback, store=False)
    wrpcap(output_file, packets)

if __name__ == "__main__":
    interface = "eth0"  # Change this to your network interface
    output_file = "captured_packets.pcap"
    start_sniffing(interface, output_file)