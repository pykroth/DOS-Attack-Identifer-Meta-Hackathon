from scapy.all import sniff

def packet_callback(packet):
    print(packet.show())  # Print the details of the captured packet

# Capture IP packets, stop after 10 packets
sniff(filter="ip", prn=packet_callback, count=10)
