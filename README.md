# ⚔️ RaedPwn – Offensive Security Toolkit (April 2025)

**RaedPwn** is a lightweight offensive security automation tool developed during my **Ethical Hacking PFA (Jan–Apr 2025)**.  
It centralizes several penetration-testing tasks such as scanning, enumeration, ARP spoofing, and exploit-helper modules used inside my virtual pentest lab.

The goal was to streamline repetitive attacker operations while learning Python-based offensive tooling.

---

## 🚀 Features

### 🔍 1. Network Scanning  
Provided by **scanner.py**

- Host discovery  
- Port scanning  
- Service identification  
- Banner grabbing  
- Quick recon shortcuts  

---

### 🕵️ 2. Attack Modules  
Provided by **attacks.py**

- ARP spoofing  
- Basic MITM setup  
- Local network mapping  
- Utility attacker operations  

---

### 💥 3. Exploit Helper Scripts  
Provided by **exploits.py** and **ms17.py**

RaedPwn includes **non-malicious exploit wrappers** that automate setup steps for:

- **MS17-010 (EternalBlue) preparation**  
- SMB vulnerability checks  
- vsftpd exploitation workflow  
- Metasploitable RCE modules  

⚠️ *These scripts do NOT contain actual exploit payloads — only automation helpers for lab simulation.*

---

## 📦 Repository Structure

```
RaedPwn/
│
├── main.py          # Main CLI entry point
├── scanner.py       # Network scanning & enumeration module
├── attacks.py       # ARP spoofing & MITM tools
├── exploits.py      # Exploit workflow helpers
├── ms17.py          # EternalBlue automation helper
├── requirements.txt # Python dependencies
└── README.md
```

---

## 🖥️ Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the main tool:

```bash
python3 main.py
```

Menu example:

```
[1] Network Scanner
[2] Attack Modules
[3] Exploit Helpers
[4] MS17-010 Tools
[0] Exit
```

---

## 🎯 Purpose

RaedPwn was built to:

- Automate repetitive pentesting steps  
- Support my PFA exploitation workflow  
- Learn Python offensive scripting  
- Integrate recon + MITM + exploit helpers in one tool  

---

## 🔒 Disclaimer

This tool was created **strictly for educational use** in an isolated lab.  
Do **NOT** use on systems you don’t own or have permission to test.

---

## 👤 Author

**Raed Boussaa**  
Telecom & Cybersecurity Engineering Student – ENIT  
