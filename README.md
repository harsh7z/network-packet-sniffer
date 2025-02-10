# network-packet-sniffer

## Overview:

The Network Packet Sniffer is a Python-based tool developed to capture and analyze network packets. This project utilizes the Scapy library for packet sniffing and allows users to monitor specific network interfaces in real-time. The sniffer captures packets such as ARP, TCP, UDP, ICMP, and others, and provides detailed information about each packet, including the source and destination IP, protocol type, and packet content.

## Features:

Packet Capture: Sniff packets from a specified network interface (e.g., en0, en1, etc.).
Real-Time Analysis: Display network traffic live as packets are captured.
Custom Filters: Apply filters to capture specific packet types (e.g., ARP, TCP, UDP) or traffic from specific IP addresses.
Multi-Interface Sniffing: Monitor multiple network interfaces simultaneously for better traffic analysis.
Packet Analysis: Extract and display useful information from packets, including the source/destination IP, packet protocol, and payload data.
Threaded Execution: Use multi-threading to capture and analyze packets concurrently without performance degradation.

## Requirements:
Python 3.x
Scapy - A Python library for network packet manipulation.

## Installation:
Clone or download the repository to your local machine.

## Install the required dependencies:
pip install scapy

Ensure you have the necessary permissions to run the sniffer. On Unix-based systems (Linux/macOS), you may need to use sudo for capturing packets:
sudo python3 network_sniffer.py

## Usage:
Run the script with the appropriate interface name. For example, to sniff on interface en0:
sudo python3 network_sniffer.py en0

You can modify the script to add custom packet filters. For instance, to capture only ARP packets, use the following filter:
sniff(prn=packet_callback, filter="arp", store=0, count=50, iface=interface)

The sniffer will start capturing and printing out packet information. You will see the following information in the output:
Source IP
Destination IP
Protocol (TCP, UDP, ICMP, ARP, etc.)
Packet length
Payload data (for deeper packet inspection)
