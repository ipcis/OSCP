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

CVE / Exploit Search
searchsploit <name>
searchsploit -p <id>
cp <path> .

Fuzzing 
python -c 'print("A" * 5000)' | nc <ip> <port>



