import nmap
import sys

# Color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def run_scan():
    try:
        target = input(f"{YELLOW}Enter target IP or CIDR for Basic Scan: {RESET}")
        scanner = nmap.PortScanner()
        print(f"{BLUE}[+] Scanning {target}...{RESET}")
        scanner.scan(hosts=target, arguments='-sS -sV -T4')

        for host in scanner.all_hosts():
            print(f"\n{GREEN}Host:{RESET} {host} ({scanner[host].hostname()})")
            print(f"{GREEN}State:{RESET} {scanner[host].state()}")

            for proto in scanner[host].all_protocols():
                print(f"{YELLOW}Protocol:{RESET} {proto.upper()}")
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    service = scanner[host][proto][port]['name']
                    state = scanner[host][proto][port]['state']
                    print(f"  {proto.upper()} Port {port}: {service} [{state}]")

    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan aborted by user.{RESET}")
        sys.exit(0)
    except nmap.PortScannerError:
        print(f"{RED}[!] Nmap not found! Install it: sudo apt install nmap{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}[!] Unexpected error: {e}{RESET}")
        sys.exit(1)

def run_advanced_scan():
            try:
                target = input(f"{YELLOW}Enter target IP or CIDR for Advanced Scan: {RESET}")
                scanner = nmap.PortScanner()
                print(f"{BLUE}[+] Running Full Aggressive Scan on {target}...{RESET}")
        
                scanner.scan(
                    hosts=target,
                    arguments='-sS -sV -sC -O --traceroute -Pn -p- -T4'
                )
        
                for host in scanner.all_hosts():
                    print(f"\n{GREEN}Host:{RESET} {host} ({scanner[host].hostname()})")
                    print(f"{GREEN}State:{RESET} {scanner[host].state()}")
        
                    for proto in scanner[host].all_protocols():
                        print(f"{YELLOW}Protocol:{RESET} {proto.upper()}")
                        ports = scanner[host][proto].keys()
                        for port in sorted(ports):
                            service = scanner[host][proto][port]['name']
                            product = scanner[host][proto][port].get('product', '')
                            version = scanner[host][proto][port].get('version', '')
                            state = scanner[host][proto][port]['state']
                            print(f"  {proto.upper()} Port {port}: {service} {product} {version} [{state}]")
        
            except KeyboardInterrupt:
                print(f"\n{RED}[!] Scan aborted by user.{RESET}")
                sys.exit(0)
            except Exception as e:
                print(f"{RED}[!] Unexpected error: {e}{RESET}")
                sys.exit(1)

def smb_enumeration():
    try:
        target = input(f"{YELLOW}Enter Windows target IP for SMB Enumeration: {RESET}")
        scanner = nmap.PortScanner()
        print(f"{BLUE}[+] Enumerating SMB Services on {target}...{RESET}")
        scanner.scan(hosts=target, arguments='-p 139,445 --script smb-enum-shares,smb-enum-users')

        for host in scanner.all_hosts():
            print(f"\n{GREEN}Host:{RESET} {host}")
            if 'tcp' in scanner[host]:
                for port in scanner[host]['tcp']:
                    print(f"{YELLOW}Port {port}:{RESET} {scanner[host]['tcp'][port]['state']} - {scanner[host]['tcp'][port]['name']}")
                    if 'script' in scanner[host]['tcp'][port]:
                        for script_output in scanner[host]['tcp'][port]['script']:
                            print(f"{GREEN}{script_output}:{RESET} {scanner[host]['tcp'][port]['script'][script_output]}")

        print(f"{GREEN}SMB ports are open :) ")

    except KeyboardInterrupt:
        print(f"\n{RED}[!] Enumeration aborted by user.{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{RED}[!] Unexpected error: {e}{RESET}")
        sys.exit(1)
