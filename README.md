# packet-sniffer-python
A simple Python-based packet sniffer for monitoring and analyzing raw network traffic.
# 🕵️ Packet Sniffer with Alerts & Visualizations

A Python-based packet sniffer that captures and analyzes network traffic in real-time.  
It supports filtering by source/destination IP and port, logs traffic with timestamps,  
detects suspicious patterns like UDP floods, and generates visualizations to better understand the captured data.

---

## 🚀 Features

- ✅ Real-time packet capture using Scapy
- 🔍 Filter by source/destination IP and ports
- 📄 Logs packet data to `packet_log.txt` with timestamps
- 🚨 Alert system for potential UDP flood detection
- 📊 Visualizations: protocol usage, top talkers, traffic over time
- 💻 CLI options for flexible usage

---

## 📦 Installation

```bash
git clone https://github.com/your-username/packet-sniffer-python.git
cd packet-sniffer-python
pip install -r requirements.txt
```

> Requirements: `scapy`, `matplotlib`

---

## ⚙️ Usage

```bash
sudo python3 sniffer.py [OPTIONS]
```

### Available Options

| Flag | Description |
|------|-------------|
| `--src`        | Filter by source IP address |
| `--dst`        | Filter by destination IP address |
| `--src-port`   | Filter by source port |
| `--dst-port`   | Filter by destination port |
| `--count`      | Number of packets to capture (default: 20) |
| `--visualize`  | Generate traffic graphs after capture |

### Example:

```bash
sudo python3 sniffer.py --src 192.168.1.10 --dst-port 443 --count 100 --visualize
```

---

## 📊 Sample Output

![Protocol Distribution Graph](assets/protocol_pie.png)  
![Top Talkers](assets/top_ips_bar.png)  
![Packets Over Time](assets/time_histogram.png)

---

## 💡 Future Ideas

- Export to PCAP or JSON
- Detect more threat patterns (e.g., port scans, DNS tunneling)
- Add a live web dashboard
- Run as a background daemon/service

---

## 👨‍💻 Author

Developed by [Your Name](https://github.com/your-username)  
Second-year Cybersecurity Student | Passionate about Python, Networking, and Blue Teaming 🛡️

---

## 📜 License

MIT License — free to use, modify, and share.
