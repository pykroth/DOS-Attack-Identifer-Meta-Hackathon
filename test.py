from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# Dictionary to store packet counts by IP address
packet_count = defaultdict(int)
syn_count = defaultdict(int)

# Define a threshold for identifying a potential DDoS attack
PACKET_THRESHOLD = 100  # packets from a single IP in a short period
SYN_THRESHOLD = 50  # SYN packets within a short time
TIME_WINDOW = 10  # in seconds

# Time tracking for detecting spikes
start_time = time.time()

port_scan_data = defaultdict(lambda: defaultdict(int))

def packet_callback(packet):
    global start_time
    
    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    if elapsed_time > TIME_WINDOW:
        # Reset counts every TIME_WINDOW seconds
        packet_count.clear()
        syn_count.clear()
        start_time = time.time()

    # Only analyze IP packets
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        
        # Count packets by source IP
        packet_count[src_ip] += 1
        
        # Check if it's a TCP packet and if the SYN flag is set
        if packet.haslayer(TCP):
            if packet[TCP].flags == "S":  # SYN flag is set
                syn_count[src_ip] += 1

    # Check for potential DDoS based on thresholds
    if packet_count[src_ip] > PACKET_THRESHOLD:
        print(f"High chance of DDoS detected from {src_ip}: {packet_count[src_ip]} packets in {TIME_WINDOW} seconds.")
    else:
        print('hi')
    if syn_count[src_ip] > SYN_THRESHOLD:
        print(f"High chance of SYN flood DDoS detected from {src_ip}: {syn_count[src_ip]} SYN packets in {TIME_WINDOW} seconds.")

    #PORT SNIFFING
    port_sniff(packet)
    
    for ip_src, ports in port_scan_data.items():
        if len(ports) > 20:  # More than 20 unique ports scanned in the time window
            print(f"Potential port scan detected from IP {ip_src} - Scanned ports: {ports.keys()}")


def port_sniff(packet):
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst

        sport = packet['TCP'].sport
        dport = packet['TCP'].dport

        timestamp = time.time()
        port_scan_data[ip_src][dport] += 1


# Start sniffing packets
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(filter="ip", prn=packet_callback, store=0)
