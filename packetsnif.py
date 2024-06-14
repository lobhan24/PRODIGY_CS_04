from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 1:  # ICMP
            proto = 'ICMP'
        elif protocol == 6:  # TCP
            proto = 'TCP'
        elif protocol == 17:  # UDP
            proto = 'UDP'
        else:
            proto = 'Other'
        
        print(f'IP Packet: {ip_src} -> {ip_dst} (Protocol: {proto})')
        
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f'TCP Payload: {bytes(tcp_layer.payload)}')
        
        if packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f'UDP Payload: {bytes(udp_layer.payload)}')
        
        if packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            print(f'ICMP Payload: {bytes(icmp_layer.payload)}')

def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
