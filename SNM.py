from scapy.all import sniff
from scapy.layers.inet import IP, TCP
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
flagged_ips = []
lock = threading.Lock()

def process_packet(pkt):
    now = time.time()
    src_ip = pkt[IP].src
    des_ip = pkt[IP].dst
    des_port = pkt[TCP].dport
    flag = str(pkt[TCP].flags)
    with lock:
        windows[src_ip].append((now, des_port, flag))
    if src_ip not in flagged_ips:
        with lock:
            windows[src_ip] = [(ts, port, flag) for (ts, port, flag) in windows[src_ip] if now - ts <= ftimer]
            dif_ports = set(port for (ts, port, flag) in windows[src_ip])

        if len(dif_ports) >= scan_ports:
            with lock:
                flagged_ips.append(src_ip)
            # will add here the flag alert!!

        elif len(dif_ports) >= susp_ports:
            severity = "suspicious"
            db.log_event(now, src_ip, des_ip, des_port, flag, severity)

def cleaner():
    while True:
        time.sleep(cleaner_sweep_time)
        now = time.time()
        for src_ip in list(windows.keys()):
            if src_ip not in flagged_ips:
                with lock:
                    windows[src_ip] = [(ts, port, flag) for (ts, port, flag) in windows[src_ip] if now - ts <= ftimer]
                    if not windows[src_ip]:
                        del windows[src_ip]
            else:
                with lock:
                    times = [ts for (ts, _, _) in windows[src_ip]]
                if times and now - max(times) > flagtimer:
                    seen = []
                    with lock:
                        for (ts, port, flag) in windows[src_ip]:
                            if port not in seen:
                                seen.append(port)
                    with lock:
                        flags = [flag for (ts, port, flag) in windows[src_ip]]

                    ports_text = ",".join(str(p) for p in seen)
                    port_count = len(seen)
                    duration = max(times) - min(times)

                    if "R" in flags:
                        db.log_scan(now, src_ip, ports_text, port_count, duration, "stealth")
                        with lock:
                            del windows[src_ip]
                            flagged_ips.remove(src_ip)
                    else:
                        db.log_scan(now, src_ip, ports_text, port_count, duration, "connect")
                        with lock:
                            del windows[src_ip]
                            flagged_ips.remove(src_ip)

t = threading.Thread(target=cleaner, daemon=True)
t.start()
sniff(filter="tcp", prn=process_packet, iface=scan_interface)