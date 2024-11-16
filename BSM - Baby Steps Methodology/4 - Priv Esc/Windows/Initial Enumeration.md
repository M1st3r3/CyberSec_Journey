
# System Enumeration

Info about the system like ```Hostname,OS,CPU Archi```
```cmd
sysinfo
systeminfo | findstr /B/C:"OS Name" /C:"OS Version" /C: "System Type"
```

To see patches:
```cmd
wmic qfe
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

To list drives on the system
```cmd
wmic logicaldisk get caption,description,providername
```

# User Enumeration

See our user
```cmd
whoami
```

Look at our current privileges
```cmd
whoami /priv
```

To see what groups we are in
```cmd
whoami /groups
```

To see users on the local machine
```cmd
net user
```

More info about a user:
```
net user [username]
```

To see what local groups are there in the machine
```cmd
net localgroup
```

To see a particular group members
```cmd
net localgroup [Group_Name]
```

# Network Enumeration

Info about the network (DNS,IP,GATEWAY)
```cmd
ipconfig
ipconfig /all
```

Look at the arp table
```cmd
arp -a
```

To see the routing table
```cmd
route print
```

To see what ports are open
```cmd
netstat -ano
```

# Password Digging

Look for password inside files (current directory)
```cmd
findstr /si password *.txt [*.file_extension]
```

More command: [PayLoadAllTheThings](More command:[https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#search-the-registry-for-key-names-and-passwords])

# Firewall / Antivirus Enumeration

Query info about a service name that we know
```cmd
sc query [name]
sc query windefend
```

If we dont know the name we can search all running service on the machine
```cmd
sc queryex
```

To see Firewall State
```cmd
netsh advfirewall firewall dump
netsh firewall show state
```

To see configuration of Firewall
```cmd
netsh firewall show config
```

# Find a folder path by name

```cmd
dir C:\ /ad /s /b | findstr "MyFolder"
```

# Find a file path by name
```cmd
where /R c:\ [file_name]
```
# Automated Enumeration Tools

![[Pasted image 20241102184327.png]]

[WinPEAS ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

[Windows PrivEsc Checklist](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)

[Sherlock](https://github.com/rasta-mouse/Sherlock)

[Watson](https://github.com/rasta-mouse/Watson)

[Power Up](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

[JAWS](https://github.com/411Hall/JAWS)

[Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

[Metasploit Local Exploit Suggester](https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/)

[Seatbelt](https://github.com/GhostPack/Seatbelt)

[SharpUp](https://github.com/GhostPack/SharpUp)


powershell Get-Content -Path "hm.txt" -Stream "root.txt"