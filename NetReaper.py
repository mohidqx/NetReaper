#!/usr/bin/env python3
"""
TeamCyberOps NetReaper: The Complete Network Surveillance Suite
Author: Muhammad Mohid & GLM
Date: 2026-02-01
Profile: Offensive Security / Network Analysis
"""

import sys
import time
import argparse
import signal
import json
import sqlite3
import threading
import re
import psutil
from collections import defaultdict, Counter, deque
from datetime import datetime

# Third-party Imports
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTPRequest
    from scapy.layers.tls.all import TLSClientHello
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.l2 import ARP, Ether
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from colorama import Fore, Style, init
except ImportError as e:
    print(f"[-] Critical Missing Dependency: {e}")
    print("[-] Run: pip install scapy rich colorama psutil")
    sys.exit(1)

# Initialize Colors
init(autoreset=True)
console = Console()

# --- Configuration & Globals ---
CONFIG = {
    'interface': None,
    'pcap_out': None,
    'db_file': 'NetReaper.db',
    'json_file': 'NetReaper_export.json',
    'store_db': False,
    'export_json': False,
    'verbose': False, # Controlled by TUI toggle
    'debug': False    # Raw output mode
}

# Shared State (Thread-Safeish)
STATE = {
    'running': True,
    'start_time': time.time(),
    'packet_count': 0,
    'protocols': Counter(),
    'src_ips': Counter(),
    'dst_ips': Counter(),
    'alerts': [],
    'packet_log': deque(maxlen=25), # Keep last 25 for UI
    'connections_cache': {} # Cache for PID lookups
}

# Threat Signatures
SIGNATURES = {
    'CREDENTIAL': r'(?i)(user|username|pass|passwd|password|key|token|auth)=([^&]+)',
    'BASIC_AUTH': r'Authorization: Basic [a-zA-Z0-9+/=]+',
    'API_KEY': r'(?i)(api[-_]?key|access[-_]?token)=([a-zA-Z0-9\-_]+)'
}

# --- Database Manager (Restored) ---
class DatabaseManager:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = None
        self.cursor = None
        self.lock = threading.Lock()

    def connect(self):
        try:
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
            self.cursor = self.conn.cursor()
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip TEXT, dst_ip TEXT,
                    src_port INTEGER, dst_port INTEGER,
                    protocol TEXT, size INTEGER,
                    info TEXT, process TEXT
                )
            ''')
            self.conn.commit()
        except Exception as e:
            print(f"[!] DB Error: {e}")

    def insert(self, data):
        if not self.conn: return
        with self.lock:
            try:
                self.cursor.execute('''
                    INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size, info, process)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', data)
                self.conn.commit()
            except: pass

    def close(self):
        if self.conn: self.conn.close()

# --- Helper Functions ---

def get_process_name(port, proto='tcp'):
    """Identify the local process (PID/Name) using the port."""
    # Simple cache to avoid high CPU usage
    cache_key = f"{proto}:{port}"
    if cache_key in STATE['connections_cache']:
        # Invalidate cache every few seconds implicitly by overwriting later? 
        # For now, return cached if recent.
        pass

    try:
        # Scan system connections
        kind = 'tcp' if proto == 'TCP' else 'udp'
        for conn in psutil.net_connections(kind=kind):
            if conn.laddr.port == port:
                proc = psutil.Process(conn.pid)
                name = f"{proc.name()} ({conn.pid})"
                STATE['connections_cache'][cache_key] = name
                return name
    except:
        pass
    return "Unknown"

def get_sni(pkt):
    """Extract SNI from TLS."""
    if pkt.haslayer(TLSClientHello):
        try:
            return pkt[TLSClientHello].extensions[0].servernames[0].servername.decode()
        except: pass
    return None

def analyze_payload(pkt):
    """Scan for credentials."""
    if not pkt.haslayer(Raw): return None
    try:
        load = pkt[Raw].load.decode('utf-8', errors='ignore')
        for label, regex in SIGNATURES.items():
            match = re.search(regex, load)
            if match:
                return f"[bold red]!! {label} !![/bold red] {match.group(0)[:30]}..."
    except: pass
    return None

# --- Packet Processing Core ---

def process_packet(pkt):
    global STATE
    
    STATE['packet_count'] += 1
    ts = datetime.now().isoformat()
    
    # Defaults
    src, dst = "Unknown", "Unknown"
    sport, dport = 0, 0
    proto = "ETH"
    info = ""
    process_info = "-"
    alert_msg = None

    # Layer 3
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
        STATE['src_ips'][src] += 1
        STATE['dst_ips'][dst] += 1
    
    # Layer 4 & 7
    if pkt.haslayer(TCP):
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        
        # High Feature: Process Mapping (Local only)
        # Check if traffic is originating from or destined to this machine
        process_info = get_process_name(sport, 'TCP') if sport > 1024 else get_process_name(dport, 'TCP')

        if dport == 80 or sport == 80:
            proto = "HTTP"
            if pkt.haslayer(HTTPRequest):
                info = f"{pkt[HTTPRequest].Method.decode()} {pkt[HTTPRequest].Host.decode()}"
                alert_msg = analyze_payload(pkt)
        elif dport == 443 or sport == 443:
            proto = "TLS"
            sni = get_sni(pkt)
            info = f"SNI: {sni}" if sni else "Encrypted"
            
    elif pkt.haslayer(UDP):
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            proto = "DNS"
            try: info = f"Query: {pkt[DNSQR].qname.decode()}"
            except: pass

    STATE['protocols'][proto] += 1
    
    if alert_msg:
        STATE['alerts'].append(alert_msg)
        info = alert_msg # Override info with the alert

    # Store in DB
    if CONFIG['store_db'] and db_manager:
        db_manager.insert((ts, src, dst, sport, dport, proto, len(pkt), info, process_info))

    # Update UI Log
    log_entry = {
        'time': datetime.now().strftime('%H:%M:%S'),
        'process': process_info,
        'proto': "ALERT" if alert_msg else proto,
        'src': src,
        'dst': dst,
        'info': info
    }
    STATE['packet_log'].appendleft(log_entry)

    # Raw Debug Mode
    if CONFIG['debug']:
        print(f"[RAW] {proto} | {src}:{sport} -> {dst}:{dport} | {info}")

    # PCAP Save
    if CONFIG['pcap_out']:
        wrpcap(CONFIG['pcap_out'], pkt, append=True)

# --- UI Layout & Rendering ---

def get_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    layout["body"].split_row(
        Layout(name="feed", ratio=3),
        Layout(name="stats", ratio=1)
    )
    return layout

def update_display(layout):
    # Header
    runtime = int(time.time() - STATE['start_time'])
    status = "[bold green]ACTIVE[/bold green]" if STATE['running'] else "[bold red]STOPPED[/bold red]"
    
    header_table = Table.grid(expand=True)
    header_table.add_column(justify="left")
    header_table.add_column(justify="right")
    header_table.add_row(
        f"[bold cyan]NetReaper[/bold cyan] | Iface: {CONFIG['interface']} | {status}",
        f"Pkts: {STATE['packet_count']} | Time: {runtime}s | DB: {'ON' if CONFIG['store_db'] else 'OFF'}"
    )
    layout["header"].update(Panel(header_table, style="white on black"))

    # Log Feed
    feed_table = Table(expand=True, box=box.SIMPLE_HEAD, border_style="dim")
    feed_table.add_column("Time", width=8, style="dim")
    feed_table.add_column("App/Process", width=15, style="cyan")
    feed_table.add_column("Proto", width=6)
    feed_table.add_column("Source", style="green")
    feed_table.add_column("Destination", style="blue")
    feed_table.add_column("Payload / Info", style="white")

    for row in STATE['packet_log']:
        style_p = "white"
        if row['proto'] == "TCP": style_p = "green"
        elif row['proto'] == "UDP": style_p = "yellow"
        elif row['proto'] == "DNS": style_p = "magenta"
        elif "ALERT" in row['proto']: style_p = "bold red blink"

        feed_table.add_row(
            row['time'], row['process'], f"[{style_p}]{row['proto']}[/]", 
            row['src'], row['dst'], row['info']
        )
    layout["feed"].update(Panel(feed_table, title="Live Interception Feed"))

    # Stats Side Panel
    stats_table = Table(title="Top Talkers", box=box.SIMPLE)
    stats_table.add_column("IP")
    stats_table.add_column("#")
    for ip, count in STATE['src_ips'].most_common(10):
        stats_table.add_row(ip, str(count))
    
    proto_table = Table(title="Protocols", box=box.SIMPLE)
    proto_table.add_column("Proto")
    proto_table.add_column("#")
    for p, c in STATE['protocols'].most_common():
        proto_table.add_row(p, str(c))
        
    stats_panel = Layout()
    stats_panel.split_column(Layout(Panel(stats_table)), Layout(Panel(proto_table)))
    layout["stats"].update(stats_panel)

    # Footer (Alerts)
    footer_text = "System Secure."
    if STATE['alerts']:
        footer_text = f"[bold red]THREAT DETECTED:[/bold red] {STATE['alerts'][-1]}"
    layout["footer"].update(Panel(footer_text, border_style="red" if STATE['alerts'] else "green"))

# --- Main Execution ---

db_manager = None

def main():
    global db_manager

    parser = argparse.ArgumentParser(description="TeamCyberOps Network Suite")
    parser.add_argument("-i", "--interface", help="Interface (e.g., eth0)")
    parser.add_argument("-w", "--write", help="Write to PCAP")
    parser.add_argument("--db", action="store_true", help="Enable SQLite logging")
    parser.add_argument("--json", action="store_true", help="Export JSON on exit")
    parser.add_argument("--debug", action="store_true", help="Debug Mode (No UI)")
    
    args = parser.parse_args()
    
    CONFIG['interface'] = args.interface or conf.iface
    CONFIG['pcap_out'] = args.write
    CONFIG['store_db'] = args.db
    CONFIG['export_json'] = args.json
    CONFIG['debug'] = args.debug

    # Database Setup
    if CONFIG['store_db']:
        db_manager = DatabaseManager(CONFIG['db_file'])
        db_manager.connect()
        print(f"[*] Database Active: {CONFIG['db_file']}")

    print(f"[*] Starting TeamCyberOps NetReaper on {CONFIG['interface']}...")

    # Start Sniffer Thread
    # We use AsyncSniffer so it doesn't block the UI loop
    sniffer = AsyncSniffer(
        iface=CONFIG['interface'],
        prn=process_packet,
        store=0
    )
    sniffer.start()

    try:
        if CONFIG['debug']:
            # Debug Mode: Just keep main thread alive
            while True: time.sleep(1)
        else:
            # UI Mode
            layout = get_layout()
            with Live(layout, refresh_per_second=4, screen=True):
                while True:
                    update_display(layout)
                    time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[*] Stopping TeamCyberOps NetReaper...")
        STATE['running'] = False
        if sniffer.running: sniffer.stop()
        
        if db_manager:
            db_manager.close()
            
        if CONFIG['export_json']:
            print(f"[*] Exporting JSON to {CONFIG['json_file']}...")
            data = {
                'summary': {
                    'total': STATE['packet_count'],
                    'duration': time.time() - STATE['start_time'],
                    'protocols': dict(STATE['protocols'])
                },
                'top_ips': dict(STATE['src_ips'].most_common(20))
            }
            with open(CONFIG['json_file'], 'w') as f:
                json.dump(data, f, indent=2)
            print("[+] Export Complete.")

if __name__ == "__main__":
    main()
