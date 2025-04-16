import argparse
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict, Counter
import time
import matplotlib.pyplot as plt

log_file = "packet_log.txt"

# Data for stats and alerts
packet_counts = defaultdict(list)
protocol_counts = Counter()
ip_counter = Counter()
time_series = []

# Packet processing
def packet_callback(packet, src_ip, dst_ip, src_port, dst_port):
    if IP not in packet:
        return

    ip_layer = packet[IP]
    now = time.time()
    time_series.append(now)

    # Apply filters
    if src_ip and ip_layer.src != src_ip:
        return
    if dst_ip and ip_layer.dst != dst_ip:
        return

    proto = None
    transport = None
    if TCP in packet:
        proto = "TCP"
        transport = packet[TCP]
    elif UDP in packet:
        proto = "UDP"
        transport = packet[UDP]
    else:
        return

    if src_port and transport.sport != src_port:
        return
    if dst_port and transport.dport != dst_port:
        return

    # Update stats
    ip_counter[ip_layer.src] += 1
    protocol_counts[proto] += 1
    packet_counts[ip_layer.src].append(now)
    packet_counts[ip_layer.src] = [t for t in packet_counts[ip_layer.src] if now - t < 10]

    if len(packet_counts[ip_layer.src]) > 30:
        print(f"\n\u26a0\ufe0f ALERT: Possible UDP flood from {ip_layer.src} ({len(packet_counts[ip_layer.src])} packets in 10s)")

    # Format log
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_lines = [
        f"[{timestamp}]",
        f"[IP] {ip_layer.src} → {ip_layer.dst} | Protocol: {proto}",
        f"   [{proto}] Port {transport.sport} → {transport.dport}"
    ]
    if proto == "TCP":
        log_lines[-1] += f" | Flags: {transport.flags}"

    # Output
    print("\n".join(log_lines))
    with open(log_file, "a") as f:
        f.write("\n".join(log_lines) + "\n\n")

# Visualization after sniff ends
def visualize_results():
    # Protocol distribution
    if protocol_counts:
        plt.figure(figsize=(6,6))
        plt.title("Protocol Distribution")
        plt.pie(list(protocol_counts.values()), labels=list(protocol_counts.keys()), autopct="%1.1f%%")
        plt.show()

    # Top talkers
    if ip_counter:
        top_ips = ip_counter.most_common(5)
        ips, counts = zip(*top_ips)
        plt.figure()
        plt.bar(ips, counts)
        plt.title("Top Source IPs")
        plt.xlabel("IP Address")
        plt.ylabel("Packet Count")
        plt.show()

    # Time histogram
    if time_series:
        from datetime import datetime
        times = [datetime.fromtimestamp(t) for t in time_series]
        plt.figure()
        plt.hist(times, bins=10)
        plt.title("Packets Over Time")
        plt.xlabel("Time")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

# CLI and sniff logic
def main():
    parser = argparse.ArgumentParser(description="Advanced Python Packet Sniffer")
    parser.add_argument("--src", help="Source IP address")
    parser.add_argument("--dst", help="Destination IP address")
    parser.add_argument("--src-port", type=int, help="Source port")
    parser.add_argument("--dst-port", type=int, help="Destination port")
    parser.add_argument("--count", type=int, default=20, help="Number of packets to capture")
    parser.add_argument("--visualize", action="store_true", help="Show graphs after sniffing")
    args = parser.parse_args()

    print("\nSniffing packets... Press Ctrl+C to stop.\n")

    sniff(
        prn=lambda pkt: packet_callback(pkt, args.src, args.dst, args.src_port, args.dst_port),
        count=args.count
    )

    if args.visualize:
        visualize_results()

if __name__ == "__main__":
    main()
