# 🛡️ Pyshark Network Packet Logger & Redis MQ Producer

High-speed network packet sniffer powered by **PyShark** (Wireshark/TShark) and **Redis Message Broker**.
Captures live network packets on any interface or replays static PCAP files, normalizes layer metadata (HTTP, TLS/SNI, DNS, Email, File Transfers) into the exact 30-dimension feature format expected by the AI/ML backend, and streams them into Redis MQ (`network_logs_queue`).

---

## 🚀 Key Features

1. **Protocol Deep Inspection**:
   - **HTTP**: Extracts request methods, Host, URI, URL, User-Agent, headers (`X-User-Id`), content lengths, and response sizes.
   - **TLS / HTTPS**: Extracts Server Name Indication (SNI) from TLS Handshakes to identify encrypted destination domains (e.g. `wikileaks.org`, `dropbox.com`).
   - **DNS**: Captures query names (`dns.qry_name`).
   - **Email Protocols**: Detects SMTP / IMAP / POP3 traffic, message sizes, recipients (`to`, `bcc`).
   - **File Transfers**: Identifies sensitive document and archive downloads/uploads (`.pdf`, `.docx`, `.zip`, `.exe`, `.tar`, `.bin`).
2. **Temporal & Identity Mapping**:
   - Automatic classification of after-hours traffic (outside 07:30 - 18:30 or weekends).
   - Identity resolution via headers (`X-User-Id`) or IP-to-User lookup mapping table.
3. **Decoupled Line-Speed Producer**:
   - Fast synchronous/pipelined Redis `LPUSH` into `network_logs_queue`.

---

## 📦 Usage

### 1. Live Interface Sniffing
```bash
# Capture packets on loopback interface
uv run --directory logger python main.py sniff --interface lo

# Capture packets with BPF filter on specific interface
uv run --directory logger python main.py sniff --interface eth0 --bpf "tcp port 80 or port 443" --user AAM0658
```

### 2. PCAP File Replay
```bash
uv run --directory logger python main.py pcap sample_traffic.pcap --redis-url redis://localhost:6379/0
```
