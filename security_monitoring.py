from scapy.all import sniff, IP, TCP

port_scan_count = {}

def detect_port_scan(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        if src_ip not in port_scan_count:
            port_scan_count[src_ip] = set()
        port_scan_count[src_ip].add(dst_port)
        if len(port_scan_count[src_ip]) > 10:  # Threshold for port scanning
            print(f"Possible Port Scan Detected from {src_ip}")

def start_sniffing(interface):
    sniff(iface=interface, prn=detect_port_scan, store=False)

if __name__ == "__main__":
    interface = "eth0"  # Change this to your network interface
    start_sniffing(interface)