import subprocess
import threading
import os
import sys
import time
import json
import IDS_banner 

# Paths to Suricata files
LOG_FILE = "/var/log/suricata/log.json"
SURICATA_LOG_DIR = "/var/log/suricata"

# Global interface variable
INTERFACE = None

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def start_icmp_ids():
    clear_screen()
    IDS_banner.print_banner()
    print("[+] Starting live ICMP packet capture and Suricata analysis...\n")

def choose_interface():
    """Lists available interfaces and allows the user to choose one cleanly."""
    try:
        result = subprocess.run(["tshark", "-D"], capture_output=True, text=True)
        interfaces_output = result.stdout.strip().splitlines()

        if not interfaces_output:
            print("No network interfaces found. Make sure tshark is installed and run with sudo.")
            sys.exit(1)

        print("\nAvailable interfaces:")
        for line in interfaces_output:
            print(line)

        choice = input("\nEnter interface number or name: ").strip()

        # If user entered a number, map it to the interface name
        if choice.isdigit():
            try:
                interface_line = interfaces_output[int(choice) - 1]
                interface_name = interface_line.split(".")[1].strip()
                return interface_name
            except (IndexError, ValueError):
                print("Invalid choice. Please try again.")
                sys.exit(1)
        else:
            return choice

    except FileNotFoundError:
        print("tshark not found. Install it with: sudo apt install tshark")
        sys.exit(1)


def run_suricata():
    """Runs Suricata as a background process."""
    print(f"[+] Launching Suricata on interface: {INTERFACE}")
    subprocess.Popen([
        "sudo", "suricata",
        "-i", INTERFACE,
        "-l", SURICATA_LOG_DIR
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def monitor_eve():
    """Continuously monitors Suricata’s eve.json for alerts."""
    last_size = 0
    print("[+] Monitoring Suricata alerts...\n")

    while True:
        try:
            if os.path.exists(LOG_FILE):
                current_size = os.path.getsize(LOG_FILE)
                if current_size < last_size:
                    last_size = 0 

                with open(LOG_FILE, "r") as f:
                    f.seek(last_size)
                    new_data = f.read()
                    last_size = f.tell()

                for line in new_data.splitlines():
                    try:
                        event = json.loads(line)
                        if event.get("event_type") == "alert":
                            alert = event["alert"]
                            src = event.get("src_ip", "?")
                            dst = event.get("dest_ip", "?")
                            sig = alert.get("signature", "Unknown alert")
                            print(f"\033[91m[ALERT]\033[0m {sig} | SRC: {src} → DST: {dst}")
                    except json.JSONDecodeError:
                        continue

            time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Stopping Suricata...")
            subprocess.run(["sudo", "pkill", "suricata"])
            break


def main():
    global INTERFACE
    start_icmp_ids()
    sys.stderr.write("\nThis program requires root access for full functionality!\n")

    INTERFACE = choose_interface()

    # Run Suricata in background
    run_suricata()

    # Start alert monitor in a separate thread
    alert_thread = threading.Thread(target=monitor_eve, daemon=True)
    alert_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Exiting program.")
        subprocess.run(["sudo", "pkill", "suricata"])


if __name__ == "__main__":
    main()
