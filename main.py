from scanner import run_scan  # We'll later update this
from scanner import run_advanced_scan  # We'll later update this
from scanner import smb_enumeration  # We'll later update this
from attacks import run_arpspoof
from exploits import exploit_vsftpd, exploit_distcc
from ms17 import exploit_eternalblue, generate_payload, drop_payload_via_msf, start_listener

# Simple color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_main_menu():
    print(rf"""{BLUE}


 ____  _____ _    ____ _____           _ 
|  _ \|  ___/ \  |___ \_   _|__   ___ | |
| |_) | |_ / _ \   __) || |/ _ \ / _ \| |
|  __/|  _/ ___ \ / __/ | | (_) | (_) | |
|_|   |_|/_/   \_\_____||_|\___/ \___/|_|


    -------------------------------------
    {YELLOW}[1]{RESET} Scan your network
    {YELLOW}[2]{RESET} Network attacks
    {YELLOW}[3]{RESET} Metasploitable attacks
    {YELLOW}[4]{RESET} Windows attacks
    {YELLOW}[0]{RESET} Exit
    """)

def print_scan_menu():
    print(f"""
{BLUE}--- Scan Your Network ---{RESET}
{YELLOW}[1]{RESET} Basic Network Scan
{YELLOW}[2]{RESET} Advanced Nmap Scan
{YELLOW}[3]{RESET} SMB Enumeration (Windows)
{YELLOW}[0]{RESET} Return to Main Menu
""")

def print_network_attack_menu():
    print(f"""
{BLUE}--- Network Attacks ---{RESET}
{YELLOW}[1]{RESET} ARP Spoof Attack
{YELLOW}[0]{RESET} Return to Main Menu
""")

def print_metasploitable_menu():
    print(f"""
{BLUE}--- Metasploitable Exploits ---{RESET}
{YELLOW}[1]{RESET} Exploit vsftpd
{YELLOW}[2]{RESET} Exploit distcc
{YELLOW}[0]{RESET} Return to Main Menu
""")

def print_windows_menu():
    print(f"""
{BLUE}--- Windows Exploits ---{RESET}
{YELLOW}[1]{RESET} Exploit EternalBlue + Lateral Movement
{YELLOW}[0]{RESET} Return to Main Menu
""")

def main():
    while True:
        print_main_menu()
        choice = input(f"PFA2Tool >> ")

        if choice == '1':  # Scan
            while True:
                  print_scan_menu()
                  scan_choice = input(f"scan >> ")
                  if scan_choice == '1':
                        run_scan()
                  elif scan_choice == '2':
                      run_advanced_scan()
                  elif scan_choice == '3':
                       smb_enumeration()
                  elif scan_choice == '0':
                      break
                  else:
                      print(f"{RED}[!] Invalid scan choice{RESET}")

        elif choice == '2':  # Network attacks
            while True:
                print_network_attack_menu()
                attack_choice = input(f"attack >> ")
                if attack_choice == '1':
                    run_arpspoof()
                elif attack_choice == '0':
                    break
                else:
                    print(f"{RED}[!] Invalid attack choice{RESET}")

        elif choice == '3':  # Metasploitable exploits
            while True:
                print_metasploitable_menu()
                meta_choice = input(f"metasploitable >> ")
                if meta_choice == '1':
                    ip = input("Target IP for vsftpd: ")
                    exploit_vsftpd(ip)
                elif meta_choice == '2':
                    ip = input("Target IP for distcc: ")
                    exploit_distcc(ip)
                elif meta_choice == '0':
                    break
                else:
                    print(f"{RED}[!] Invalid metasploitable choice{RESET}")

        elif choice == '4':  # Windows exploits
            while True:
                print_windows_menu()
                win_choice = input(f"windows >> ")
                if win_choice == '1':
                    attacker_ip = input("Enter your IP address: ")
                    target_ip = input("Enter the target (Windows 7) IP address: ")
                    filename = input("Enter payload filename (default: update.exe): ") or "update.exe"
                    session_id = int(input("Enter Meterpreter session ID (default: 1): ") or 1)

                    exploit_eternalblue(target_ip, attacker_ip)
                    generate_payload(attacker_ip, filename)
                    drop_payload_via_msf(attacker_ip, filename, session_id)
                    start_listener(attacker_ip)
                elif win_choice == '0':
                    break
                else:
                    print(f"{RED}[!] Invalid Windows exploit choice{RESET}")

        elif choice == '0':
            print(f"{GREEN}[*] Exiting...{RESET}")
            break

        else:
            print(f"{RED}[!] Invalid choice{RESET}")

if __name__ == "__main__":
    main()
