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
    print("[*] Suricata started...\n")
    try:
        subprocess.run([
            "suricata",
            "-i", interface,
            "-l", SURICATA_LOG_DIR
        ])
    except Exception as e:
        print(f"[!] Suricata error: {e}")


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
                            continue

            time.sleep(1)

        except KeyboardInterrupt:
            print("\n[!] Stopping alert monitor...")
            break


def main():
    if os.geteuid() != 0:
        sys.stderr.write("Please run this script as root (e.g. sudo python3 main.py)\n")
        sys.exit(1)

    start_icmp_ids()
    sys.stderr.write("\nThis program requires root access for full functionality!\n")


    p1 = subprocess.run(["tshark", "-D"], capture_output=True, text=True)
    raw_interfaces = p1.stdout.strip().splitlines()

    interfaces = []
    for line in raw_interfaces:
        parts = line.split(".", 1)
        if len(parts) == 2:
            idx = parts[0].strip()
            name = parts[1].split("(", 1)[0].strip()
            interfaces.append((idx, name))

    print("\nAvailable interfaces:\n")
    for idx, name in interfaces:
        print(f"{idx}. {name}")

    choice = input("\nChoose interface number: ").strip()

    selected = None
    for idx, name in interfaces:
        if choice == idx:
            selected = name
            break

    if not selected:
        print("[!] Invalid selection.")
        sys.exit(1)

    global interface
    interface = selected
    print(f"\n[+] Selected interface: {interface}\n")

    # Validate interface
    if not os.path.exists(f"/sys/class/net/{interface}"):
        print(f"[!] Interface '{interface}' does not exist.")
        sys.exit(1)

    # Start Suricata
    suricata_thread = threading.Thread(target=run_suricata, daemon=True)
    suricata_thread.start()

    # Start alert monitor
    alert_thread = threading.Thread(target=monitor_suricata_alerts, daemon=True)
    alert_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Exiting IDS...")
        sys.exit(0)


if __name__ == "__main__":
    main()
