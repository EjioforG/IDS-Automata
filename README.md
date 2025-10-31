===========================================================
         🛰️  Project Rewire: ICMP IDS Automation
===========================================================

An Automated Intrusion Detection System powered by Suricata

🔹 Overview
Project Rewire is an Intrusion Detection System (IDS) automation built around Suricata.
It monitors and analyzes network traffic in real time, automatically handling alerts,
parsing logs, and simplifying the detection workflow.

Originally, this project started as an attempt to build a custom IDS from scratch —
but after hitting a few walls, the idea evolved into automating Suricata for smarter,
faster, and more reliable detection.


🔹 DESCRIPTION
This is a Python-based Intrusion Detection System (IDS) that automates Suricata
to monitor ICMP (ping) traffic in real-time.
It detects suspicious or abnormal patterns by leveraging Suricata's alert engine
and displays results directly in your terminal.


🔹 HOW IT WORKS
1. The banner displays a colored ASCII header (from icmp_ids_banner.py).
2. Suricata is launched on your selected network interface.
3. Suricata writes alerts into: /var/log/suricata/eve.json
4. The Python script monitors eve.json in real-time and prints
   new ICMP-related alerts (like ping floods, etc).


🔹 SYSTEM REQUIREMENTS
- Linux (recommended: Kali Linux or Ubuntu)
- Suricata (configured and running)
- Python 3.8+


🔹 DEPENDENCIES
Make sure you have the following installed:
    • tshark
    • Root privileges (sudo)
    • Python libraries from requirements.txt

Install them using:
    pip install -r requirements.txt


🔹 RUNNING THE PROGRAM
Run this script as root:
    sudo python3 main.py

When prompted, select your network interface
(e.g., eth0, wlan0, enp0s3, etc.)


🔹 FILE STRUCTURE
    ├── main.py                # Main IDS script
    ├── icmp_ids_banner.py     # ASCII startup banner


🔹 EXAMPLE OUTPUT
    [2025-10-16 14:20:18] [ALERT] ICMP Ping Detected | SRC: 192.168.1.5 → DST: 8.8.8.8
    [2025-10-16 14:20:22] [ALERT] Potential Ping Flood | SRC: 192.168.1.10 → DST: 192.168.1.1


🔹 NOTES
• Always run with root privileges for full packet access.
• You can modify Suricata rules to customize which ICMP packets trigger alerts.
• Use Ctrl+C to stop monitoring.


## Running the Project
⚠️ Important: This program must be run as a privileged user (e.g., with `sudo`)
since it interacts with system logs and network interfaces.


## Updates
This project is still in active development.
Expect improvements, new features, and bug fixes soon.
Stay tuned for updates — more automation and visualization features are on the way!


## Disclaimer
This project is intended for educational and research purposes only.
