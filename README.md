# 👻 NetReaper (God-Mode Network Interceptor)

> **"See the Unseen. Track the Untraceable."**

NetReaper is an advanced, terminal-based network surveillance suite designed for offensive security professionals. It goes beyond standard packet sniffing by correlating network traffic with **local processes**, giving you "God Mode" visibility into exactly which application is communicating.

It features a high-performance cyberpunk TUI, real-time credential harvesting, and passive TLS analysis.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-red)

## ⚡ Key Capabilities

* **🖥️ NetReaper TUI:** A live, non-blocking dashboard powered by `Rich`. Monitors active connections, bandwidth, and threats in real-time.
* **🕵️ God-Mode Process Mapping:** Identifies the **Process Name** and **PID** (e.g., `discord.exe (1540)`) responsible for every packet sent or received.
* **🔓 Credential Hunter:** Automatically regex-scans HTTP payloads for `password`, `token`, `api_key`, and `Authorization` headers. Flashes **RED** alerts on detection.
* **🔐 Passive TLS Stripping:** Extracts the **SNI (Server Name)** from encrypted HTTPS handshakes to reveal visited domains without breaking encryption.
* **💾 Full Persistence:**
    * **SQLite:** logs to `NetReaper_logs.db`.
    * **JSON:** Export summaries for reporting.
    * **PCAP:** Standard capture files for Wireshark.

## 🛠️ Installation

NetReaper requires **Python 3.8+** and `libpcap` drivers.

### 1. Clone
    git clone https://github.com/mohidqx/NetReaper.git

    cd NetReaper

### 2. Install Deps
    pip install scapy rich colorama psutil

Note: Run as Root/Administrator to enable Process Mapping and Sniffing.

## 🚀 Usage
Live Dashboard (Default)

    sudo python3 NetReaper.py -i eth0

Full Surveillance (DB + PCAP)

    sudo python3 NetReaper.py -i eth0 --db -w evidence.pcap

Stealth/Debug Mode (No UI)

    sudo python3 NetReaper.py --debug

⚠️ Disclaimer
```
FOR EDUCATIONAL PURPOSES ONLY. Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws.
```

    Author: Muhammad Mohid & TeamCyberOps
