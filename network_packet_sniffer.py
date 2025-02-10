from scapy.all import sniff, IP, TCP, Raw
import logging
import threading
import argparse

# Configure logging
logging.basicConfig(filename='packet_capture.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to filter and log HTTP traffic
def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = packet.proto
        payload = bytes(packet[Raw]).decode(errors='ignore')

        if packet.haslayer(Raw):
            if packet[IP].dport == 80:  # Check for HTTP traffic
                logging.info(f"HTTP Request from {source_ip} -> {dest_ip} | Payload: {payload[:100]}")

        if len(payload) > 500:  # Suspicious large payload (could be an attack)
            logging.warning(f"Large payload detected from {source_ip} -> {dest_ip} | Payload size: {len(payload)} bytes")

# Function to start sniffing and capturing packets
def start_sniffing(interface):
    sniff(prn=packet_callback, store=0, count=50, iface=interface)

# Function to handle packet sniffing from multiple interfaces
def sniff_multiple_interfaces(interfaces):
    threads = []
    for interface in interfaces:
        thread = threading.Thread(target=start_sniffing, args=(interface,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

# Main function to run the sniffer
def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument('interfaces', metavar='INTERFACE', type=str, nargs='+', help='List of network interfaces to sniff')
    args = parser.parse_args()

    sniff_multiple_interfaces(args.interfaces)
    print("Sniffing complete. Check packet_capture.log for results.")


if __name__ == '__main__':
    main()
