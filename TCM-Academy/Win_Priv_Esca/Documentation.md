Ressources : 

Fuzzy Security Guide - https://www.fuzzysecurity.com/tutorials/16.html

PayloadsAllTheThings Guide - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

Absolomb Windows Privilege Escalation Guide - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

Sushant 747's Guide (Country dependant - may need VPN) - https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html

https://github.com/TCM-Course-Resources/Windows-Privilege-Escalation-Resources?tab=readme-ov-file



╔══════════╣ Analyzing Env Files (limit 70)
-rwxr-xr-x 1 www-data www-data 326 Nov  3  2022 /var/www/chamilo/vendor/knplabs/gaufrette/.env.dist                                                                                                             
AWS_KEY=
AWS_SECRET=
AWS_BUCKET=
AZURE_ACCOUNT=
AZURE_KEY=
AZURE_CONTAINER=
FTP_HOST=ftp
FTP_PORT=21
FTP_USER=gaufrette
FTP_PASSWORD=gaufrette
FTP_BASE_DIR=/gaufrette
MONGO_URI=mongodb://mongodb:27017
MONGO_DBNAME=gridfs_test
SFTP_HOST=sftp
SFTP_PORT=22
SFTP_USER=gaufrette
SFTP_PASSWORD=gaufrette
SFTP_BASE_DIR=gaufrette

╔══════════╣ Backup folders
drwx------ 2 root root 4096 Jul  1 13:05 /etc/lvm/backup                                                                                                                                                        
drwxr-xr-x 2 root root 4096 Nov  3 00:00 /var/backups
total 800
-rw-r--r-- 1 root root  51200 Nov  3 00:00 alternatives.tar.0
-rw-r--r-- 1 root root  36825 Jul  1 12:03 apt.extended_states.0
-rw-r--r-- 1 root root   4039 Jul  1 11:57 apt.extended_states.1.gz
-rw-r--r-- 1 root root   4011 May 31 11:13 apt.extended_states.2.gz
-rw-r--r-- 1 root root   4353 Jan 20  2024 apt.extended_states.3.gz
-rw-r--r-- 1 root root      0 Nov  3 00:00 dpkg.arch.0
-rw-r--r-- 1 root root    268 Jan 20  2024 dpkg.diversions.0
-rw-r--r-- 1 root root    172 Jan 20  2024 dpkg.statoverride.0
-rw-r--r-- 1 root root 702790 Jul  1 12:03 dpkg.status.0


╔══════════╣ Backup files (limited 100)
-rwxr-xr-x 1 www-data www-data 9610 Aug 31  2023 /var/www/chamilo/main/coursecopy/import_backup.php                                                                                                             
-rwxr-xr-x 1 www-data www-data 4112 Aug 31  2023 /var/www/chamilo/main/coursecopy/create_backup.php
-rw-r--r-- 1 root root 0 Aug 10  2023 /var/lib/systemd/deb-systemd-helper-enabled/timers.target.wants/dpkg-db-backup.timer
-rw-r--r-- 1 root root 61 Jun  7 14:00 /var/lib/systemd/deb-systemd-helper-enabled/dpkg-db-backup.timer.dsh-also
-rw-r--r-- 1 root root 2403 Aug 10  2023 /etc/apt/sources.list.curtin.old
-rwxr-xr-x 1 root root 3025 May 25 21:07 /usr/bin/wsrep_sst_backup
-rwxr-xr-x 1 root root 52401 May 25 21:07 /usr/bin/wsrep_sst_mariabackup
-rwxr-xr-x 1 root root 2196 Feb 23  2024 /usr/libexec/dpkg/dpkg-db-backup
-rw-r--r-- 1 root root 355 May 25 21:07 /usr/share/man/man1/wsrep_sst_backup.1.gz
-rw-r--r-- 1 root root 347 May 25 21:07 /usr/share/man/man1/wsrep_sst_mariabackup.1.gz
-rw-r--r-- 1 root root 2747 Feb 16  2022 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 7867 Jul 16  1996 /usr/share/doc/telnet/README.old.gz
-rw-r--r-- 1 root root 416107 Dec 21  2020 /usr/share/doc/manpages/Changes.old.gz
-rwxr-xr-x 1 root root 226 Feb 17  2020 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 11849 Jul  1 11:58 /usr/share/info/dir.old
-rw-r--r-- 1 root root 13113 Jun 10 07:55 /usr/lib/modules/5.15.0-113-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 10849 Jun 10 07:55 /usr/lib/modules/5.15.0-113-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 1423 Jan 20  2024 /usr/lib/python3/dist-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-310.pyc
-rw-r--r-- 1 root root 1802 Jul 20  2023 /usr/lib/python3/dist-packages/sos/report/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 147 Dec  5  2021 /usr/lib/systemd/system/dpkg-db-backup.service
-rw-r--r-- 1 root root 138 Dec  5  2021 /usr/lib/systemd/system/dpkg-db-backup.timer
-rw-r--r-- 1 root root 44008 Dec  5  2023 /usr/lib/x86_64-linux-gnu/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rwxr-xr-x 1 root root 1086 Oct 31  2021 /usr/src/linux-headers-5.15.0-113/tools/testing/selftests/net/tcp_fastopen_backup_key.sh

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxrwxrwx 1 www-data www-data 824745 Oct 11 02:05 /tmp/linp.sh                                                                                                                                                 
-rw-r--r-- 1 root root 51200 Nov  3 00:00 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 0 Nov  3 00:00 /var/backups/dpkg.arch.0

/var/www/chamilo/app/config/configuration.php:$_configuration['db_password'] = '03F6lY3uXAP2bkW8';

