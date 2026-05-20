# Stealth-Network-Monitor
Live port-scan detector using packet sniffing. A Scapy sniffer tracks TCP traffic in memory (sliding window per source IP, counting distinct ports) to flag scans in real time. Logs to SQLite, with a planned FastAPI layer. Built to run on a Raspberry Pi alongside a Cowrie honeypot.
