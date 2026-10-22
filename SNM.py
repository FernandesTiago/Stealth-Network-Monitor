from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
import sqlite3
import time
from collections import defaultdict
import threading

# ----------------- SETTINGS -----------------

ftimer = 10       # FIFO timer
flagtimer = 300     # Flagged timer
susp_ports = 3      # amount of different ports to be considered suspicious
scan_ports = 6      # amount of different ports to be considered a scan
scan_interface = "wg0-mullvad"    # Which interface to scan
cleaner_sweep_time = 10    # Cleaner timer

# ----------------- CODE -----------------

class DataBase:
    def __init__(self):
        self.connection = sqlite3.connect("snm-logs.db")
        self.connection.execute('''
        CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        src_ip TEXT,
        des_ip TEXT,
        des_port INTEGER,
        flags TEXT,
        severity TEXT
        )''')

        self.connection.execute('''
        CREATE TABLE IF NOT EXISTS scan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        src_ip TEXT,
        ports TEXT,
        port_count INTEGER,
        duration REAL,
        scan_type TEXT
        )''')

        self.connection.commit()
        self.connection.close()

    def log_event(self, timestamp, src_ip, des_ip, des_port, flags, severity):
        with sqlite3.connect("snm-logs.db") as conn:
            conn.execute(
                "INSERT INTO events (timestamp, src_ip, des_ip, des_port, flags, severity) VALUES (?,?,?,?,?,?)",
                (timestamp, src_ip, des_ip, des_port, flags, severity)
            )

    def log_scan(self, timestamp, src_ip, ports, port_count, duration, scan_type):
        with sqlite3.connect("snm-logs.db") as conn:
            conn.execute(
                "INSERT INTO scan (timestamp, src_ip, ports, port_count, duration, scan_type) VALUES (?,?,?,?,?,?)",
                (timestamp, src_ip, ports, port_count, duration, scan_type)
            )

windows = defaultdict(list)
db = DataBase()
flagged_ips = {} # src_ip -> {"ports": set, "flags": set, "first":ts, "last": ts}
logged_ports = defaultdict(set)    # src_ip -> ports already written to events
lock = threading.Lock()

def process_packet(pkt):
    if not pkt.haslayer(TCP):
        return
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
    else:
        return
    now = time.time()
    src_ip = ip_layer.src
    des_ip = ip_layer.dst
    des_port = pkt[TCP].dport
    flag = str(pkt[TCP].flags)
    with lock:
        if src_ip in flagged_ips:
            flagged_ips[src_ip]["ports"].add(des_port)
            flagged_ips[src_ip]["flags"].add(flag)
            flagged_ips[src_ip]["last"] = now
            return
        windows[src_ip].append((now, des_port, flag))
    with lock:
        windows[src_ip] = [(ts, port, flag) for (ts, port, flag) in windows[src_ip] if now - ts <= ftimer]
        dif_ports = set(port for (ts, port, flag) in windows[src_ip])

    if len(dif_ports) >= scan_ports:
        with lock:
            window = windows.pop(src_ip)
            logged_ports.pop(src_ip, None)
            flagged_ips[src_ip] = {
                "ports": dif_ports,
                "flags": set(flag for (ts, port, flag) in window),
                "first": min(ts for (ts, port, flag) in window),
                "last": now,
            }
        # will add here the flag alert!!

    elif len(dif_ports) >= susp_ports:
        with lock:
            first_time = des_port not in logged_ports[src_ip]
            logged_ports[src_ip].add(des_port)
        if first_time:
            severity = "suspicious"
            db.log_event(now, src_ip, des_ip, des_port, flag, severity)

def cleaner():
    while True:
        time.sleep(cleaner_sweep_time)
        now = time.time()
        for src_ip in list(windows.keys()):
            with lock:
                windows[src_ip] = [(ts, port, flag) for (ts, port, flag) in windows[src_ip] if now - ts <= ftimer]
                if not windows[src_ip]:
                    del windows[src_ip]
                    logged_ports.pop(src_ip, None)

        for src_ip in list(flagged_ips.keys()):
            with lock:
                if now - flagged_ips[src_ip]["last"] <= flagtimer:
                    continue
                summary = flagged_ips.pop(src_ip)

            ports_text = ",".join(str(p) for p in sorted(summary["ports"]))
            port_count = len(summary["ports"])
            duration = summary["last"] - summary["first"]

            if "R" in summary["flags"]:
                db.log_scan(now, src_ip, ports_text, port_count, duration, "stealth")
            else:
                db.log_scan(now, src_ip, ports_text, port_count, duration, "connect")

t = threading.Thread(target=cleaner, daemon=True)
t.start()
sniff(filter="tcp", prn=process_packet, iface=scan_interface, store=False)