import subprocess
import time
import os
import threading
import json
import sys
import IDS_banner


CAPTURE_FILE = "/tmp/pingIDS.pcap"
SURICATA_LOG_DIR = "/var/log/suricata/"
EVE_FILE = os.path.join(SURICATA_LOG_DIR, "eve.json")


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def start_icmp_ids():
    IDS_banner.print_banner()
    print("[+] Starting live ICMP packet capture and Suricata analysis...\n")

def run_suricata():
    """
    Continuously analyze the latest .pcap file with Suricata.
    Suricata writes alerts to /var/log/suricata/eve.json.
    """
    print("[*] Suricata thread started...\n")
    while True:
        try:
            subprocess.run([
                "suricata",
                "-i", interface,
                "-l", SURICATA_LOG_DIR
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Suricata error: {e}")
        time.sleep(30)  


def monitor_suricata_alerts():
    """
    Monitors Suricata's eve.json log and prints new alerts in real time.
    """
    print("[*] Monitoring Suricata alerts in real time...\n")
    last_size = 0
    initialized = False

    while True:
        try:
            if os.path.exists(EVE_FILE):
                current_size = os.path.getsize(EVE_FILE)

                if not initialized:
                    last_size = current_size
                    initialized = True
                    time.sleep(2)
                    continue
                  
                if current_size < last_size:
                    last_size = 0

                with open(EVE_FILE, "r") as f:
                    f.seek(last_size)
                    new_data = f.read()
                    last_size = f.tell()

                if new_data.strip():
                    for line in new_data.splitlines():
                        try:
                            event = json.loads(line)
                            if event.get("event_type") == "alert":
                                alert = event.get("alert", {})
                                src = event.get("src_ip", "?")
                                dst = event.get("dest_ip", "?")
                                msg = alert.get("signature", "Unknown alert")
                                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                                print(f"[{ts}] [ALERT] {msg} | SRC: {src} → DST: {dst}")
                        except json.JSONDecodeError:
                            # skip bad/malformed  lines
                            continue
            time.sleep(2)
        except KeyboardInterrupt:
            print("\n[!] Stopping alert monitor...")
            break


def main():
    # require root once at startup
    if os.geteuid() != 0:
        sys.stderr.write("Please run this script as root (e.g. sudo python3 check.py)\n")
        sys.exit(1)

    start_icmp_ids()
    sys.stderr.write("\nThis program requires root access for full functionality!\n")
    # Show available interfaces
    p1 = subprocess.run(["tshark", "-D"], capture_output=True, text=True)
    interfaces = p1.stdout
    global interface
    interface = input(f"\nAvailable interfaces:\n{interfaces}\nChoose: ").strip()

    # Start threads: only one Suricata thread + alert monitor
    suricata_thread = threading.Thread(target=run_suricata)
    suricata_thread.start()
  
    try:
        suricata_thread.join()
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
        sys.exit(0)

    

if __name__ == "__main__":
    main()
