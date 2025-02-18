import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP

# Threshold for packet rate to block an IP
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Function to read IP addresses from a file
def read_ip_file(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)

# Function to check if the packet is associated with the Nimda worm
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False

# Function to log events into log files
def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")
    with open(log_file, "a") as file:
        file.write(f"{message}\n")

# Callback function to process each packet
def packet_callback(packet):
    src_ip = packet[IP].src

    # Skip if the IP is in the whitelist
    if src_ip in whitelist_ips:
        return

    # Block if the IP is in the blacklist
    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return

    # Check if the packet matches the Nimda worm pattern
    if is_nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking Nimda source IP: {src_ip}")
        return

    # Count packets from the source IP
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    # Every second, check packet rates and block if they exceed the threshold
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)

        # Reset the packet count and start time
        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    # Ensure the script is running with root privileges
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    # Load whitelist and blacklist IPs
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    # Initialize packet count and tracking variables
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")

    # Start sniffing packets and call the packet_callback function
    sniff(filter="ip", prn=packet_callback)
