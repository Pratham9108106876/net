import time
from scapy.all import sniff

packet_count = 0
start_time = time.time()

def calculate_throughput(packet):
    global packet_count
    packet_count += 1
    elapsed_time = time.time() - start_time
    if elapsed_time > 0:
        throughput = packet_count / elapsed_time
        print(f"Throughput: {throughput} packets/sec")

def start_sniffing(interface):
    sniff(iface=interface, prn=calculate_throughput, store=False)

if __name__ == "__main__":
    interface = "eth0"  # Change this to your network interface
    start_sniffing(interface)