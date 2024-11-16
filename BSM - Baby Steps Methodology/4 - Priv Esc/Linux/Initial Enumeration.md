# System Enumeration

To gather information about the system (Kernel), we can use the following command:

```shell
uname -a
cat /proc/version
```

To check the CPU architecture, run:

```shell
lscpu
```

To see what services are running, use:

```shell
ps aux
```

# User Enumeration

To identify the current user, we can run:

```shell
id
whoami
```

To check the groups the user belongs to, run:

```shell
groups
```

To list the commands that can be run with sudo privileges, use:

```shell
sudo -l
```

We can view the user accounts in the system with:

```shell
cat /etc/passwd
ls /home
```

The groups information is stored in:

```shell
cat /etc/group
```

To see the password hashes of users (if accessible), check:

```shell
cat /etc/shadow
```

A useful command for inspecting previously executed commands is:

```shell
history
```

- Essential First Steps
	1. Run `whoami` to confirm the current user.
	2. Run `sudo -l` to check sudo privileges.
	3. Run `uname -a` for system information.
	4. Run `lscpu` to check CPU architecture.
	5. Run `history` to review previous commands.

# Network Enumeration

To see the machine's IP address, use one of the following commands, depending on the Linux version:

```shell
ip a
```

or

```shell
ifconfig
```

To view the network route:

```shell
ip route
```

For the ARP table:

```shell
arp -a
```

or

```shell
ip neigh
```

To see open ports and connections, use:

```shell
netstat -ano
netstat -tnlp
```

# Password Hunting

To search for passwords within files across the filesystem, a handy command is:

```shell
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
```

Alternatively, to find files named "password":

```shell
locate password | more
```


To locate SSH keys, use the following commands:

```shell
find / -name id_rsa 2> /dev/null
```

or

```shell
find / -name authorized_keys 2> /dev/null
```

# Automated Tools

Here are some useful automated enumeration tools for privilege escalation:

- **[PEASS-ng (linPEAS)](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)**
- **[LinEnum](https://github.com/rebootuser/LinEnum)**
- **[Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)**
- **[linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)**

Always start with `linpeas` and consider running other tools if no vulnerabilities are found. Both `linpeas` and `LinEnum` provide similar functionalities.

To check for exploitable vulnerabilities, you can use `linux-exploit-suggester`

