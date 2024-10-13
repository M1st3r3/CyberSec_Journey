# Phases of Ethical Hacking

## 1. Reconnaissance
Reconnaissance is the initial phase of gathering information about a target before launching an attack. It can be performed in two ways:

- **Active**: Direct interaction with the target to gather information (e.g., using tools like Nmap).
- **Passive**: Indirect methods of gathering data without interacting with the target (e.g., searching publicly available information).

## 2. Scanning & Enumeration
In this phase, the target is scanned for vulnerabilities and weaknesses that could be exploited.

- **Nmap**: Used to discover hosts and services on a computer network.
- **Nessus**: Vulnerability scanner to detect potential exploits.
- **Nikto**: A web server scanner to check for outdated versions, vulnerabilities, and issues.
- **Dirbuster**: A tool to brute force directories and file names on web servers.

## 3. Gaining Access ("Exploitation")
This is the phase where vulnerabilities found during scanning are exploited to gain access to the target system.

## 4. Maintaining Access
Once access is gained, hackers may install backdoors or rootkits to retain control over the target system.

## 5. Covering Tracks
After gaining and maintaining access, the final step is to erase any evidence of the attack to avoid detection. This may include clearing logs, hiding files, and using anti-forensic techniques.
