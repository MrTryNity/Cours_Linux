# __TP Avancé : "Mission Ultime : Sauvegarde et Sécurisation"__



## Étape 1 : Analyse et nettoyage du serveur





1. **Lister les tâches cron pour détecter des backdoors** :


```bash
[root@vbox ~]# for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l; done
no crontab for root
no crontab for bin
no crontab for daemon
no crontab for adm
no crontab for lp
no crontab for sync
no crontab for shutdown
no crontab for halt
no crontab for mail
no crontab for operator
no crontab for games
no crontab for ftp
no crontab for nobody
no crontab for tss
no crontab for systemd-coredump
no crontab for dbus
no crontab for sssd
no crontab for chrony
no crontab for sshd
*/10 * * * * /tmp/.hidden_script
```


2. **Identifier et supprimer les fichiers cachés** :


```bash
[root@vbox ~]# find /tmp /var/tmp /home -type f -name ".*" -exec ls -l {} \;
-rwxrwxrwx. 1 attacker attacker 17 Nov 24 18:11 /tmp/.hidden_script
-rwxrwxrwx. 1 attacker attacker 18 Nov 24 18:24 /tmp/.hidden_file
-rwxrwxrwx. 1 attacker attacker 7 Nov 24 20:10 /var/tmp/.nop
-rw-r--r--. 1 attacker attacker 141 Apr 30  2024 /home/attacker/.bash_profile
-rw-r--r--. 1 attacker attacker 492 Apr 30  2024 /home/attacker/.bashrc
-rw-r--r--. 1 attacker attacker 18 Apr 30  2024 /home/attacker/.bash_logout
-rw-------. 1 attacker attacker 3 Nov 24 18:48 /home/attacker/.bash_history
-rw-r--r--. 1 attacker attacker 18 Nov 24 20:09 /home/attacker/.hidden_file
[root@vbox ~]# rm -i /tmp/.hidden_script
rm: remove regular file '/tmp/.hidden_script'? y
[root@vbox ~]# find /tmp /var/tmp /home -type f -name ".*" -exec ls -l {} \;
-rwxrwxrwx. 1 attacker attacker 18 Nov 24 18:24 /tmp/.hidden_file
-rwxrwxrwx. 1 attacker attacker 7 Nov 24 20:10 /var/tmp/.nop
-rw-r--r--. 1 attacker attacker 141 Apr 30  2024 /home/attacker/.bash_profile
-rw-r--r--. 1 attacker attacker 492 Apr 30  2024 /home/attacker/.bashrc
-rw-r--r--. 1 attacker attacker 18 Apr 30  2024 /home/attacker/.bash_logout
-rw-------. 1 attacker attacker 3 Nov 24 18:48 /home/attacker/.bash_history
-rw-r--r--. 1 attacker attacker 18 Nov 24 20:09 /home/attacker/.hidden_file
[root@vbox ~]# rm -i /tmp/.hidden_file
rm: remove regular file '/tmp/.hidden_file'? yes
[root@vbox ~]# find /tmp /var/tmp /home -type f -name ".*" -exec ls -l {} \;
-rwxrwxrwx. 1 attacker attacker 7 Nov 24 20:10 /var/tmp/.nop
-rw-r--r--. 1 attacker attacker 141 Apr 30  2024 /home/attacker/.bash_profile
-rw-r--r--. 1 attacker attacker 492 Apr 30  2024 /home/attacker/.bashrc
-rw-r--r--. 1 attacker attacker 18 Apr 30  2024 /home/attacker/.bash_logout
-rw-------. 1 attacker attacker 3 Nov 24 18:48 /home/attacker/.bash_history
-rw-r--r--. 1 attacker attacker 18 Nov 24 20:09 /home/attacker/.hidden_file
```


3. **Analyser les connexions réseau actives** :


```bash
[root@vbox ~]# ss -tulnp
Netid State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port Process
udp   UNCONN  0       0            127.0.0.1:323         0.0.0.0:*     users:(("chronyd",pid=865,fd=5))
udp   UNCONN  0       0                [::1]:323            [::]:*     users:(("chronyd",pid=865,fd=6))
tcp   LISTEN  0       128            0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=892,fd=3))
tcp   LISTEN  0       128               [::]:22             [::]:*     users:(("sshd",pid=892,fd=4))
```


## __Étape 2 : Configuration avancée de LVM__






1. **Créer un snapshot de sécurité pour `/mnt/secure_data`** :


```bash
[root@vbox ~]# lvcreate --size 100M --snapshot --name secure_data_snap /dev/vg_secure/secure_data
Logical volume "secure_data_snap" created.

[root@vbox ~]# lvdisplay
  --- Logical volume ---
  LV Path                /dev/vg_secure/secure_data
  LV Name                secure_data
  VG Name                vg_secure
  LV UUID                gMLkSZ-8Yhz-m9Hd-1jiQ-4C0G-PRVy-FYqFeJ
  LV Write Access        read/write
  LV Creation host, time vbox, 2024-11-24 18:24:53 +0100
  LV snapshot status     source of
                         secure_data_snap [active]
  LV Status              available
  open                 1
  LV Size                500.00 MiB
  Current LE             125
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  currently set to     256
  Block device           253:2

  --- Logical volume ---
  LV Path                /dev/vg_secure/secure_data_snap
  LV Name                secure_data_snap
  VG Name                vg_secure
  LV UUID                wahsG0-GL7U-FAwo-3V03-UZbd-1yZO-hbE2nD
  LV Write Access        read/write
  LV Creation host, time vbox, 2024-11-25 19:15:13 +0100
  LV snapshot status     active destination for secure_data
  LV Status              available
  open                 0
  LV Size                500.00 MiB
  Current LE             125
  COW-table size         100.00 MiB
  COW-table LE           25
  Allocated to snapshot  0.01%
  Snapshot chunk size    4.00 KiB
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  currently set to     256
  Block device           253:5

  --- Logical volume ---
  LV Path                /dev/rl_vbox/swap
  LV Name                swap
  VG Name                rl_vbox
  LV UUID                z3wCgb-7tII-XPA1-fcb9-7arD-fqGE-V1HIqV
  LV Write Access        read/write
  LV Creation host, time vbox, 2024-11-24 17:42:22 +0100
  LV Status              available
  open                 2
  LV Size                512.00 MiB
  Current LE             128
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  currently set to     256
  Block device           253:1

  --- Logical volume ---
  LV Path                /dev/rl_vbox/root
  LV Name                root
  VG Name                rl_vbox
  LV UUID                WGJSf5-HJZJ-nPZc-bTbS-fP0E-8QgG-jTh5wo
  LV Write Access        read/write
  LV Creation host, time vbox, 2024-11-24 17:42:22 +0100
  LV Status              available
  open                 1
  LV Size                <3.50 GiB
  Current LE             895
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  currently set to     256
  Block device           253:0
```


2. **Tester la restauration du snapshot** :


```bash
[root@vbox ~]# echo "Fichier de test" > /mnt/secure_data/fichier_test
[root@vbox ~]# lvcreate --size 100M --snapshot --name secure_data_snap /dev/vg_secure/secure_data
  Logical volume "secure_data_snap" created.
[root@vbox ~]# mount /dev/vg_secure/secure_data_snap /mnt/secure_data_snap
[root@vbox ~]# ls /mnt/secure_data_snap
fichier_test  lost+found  sensitive1.txt  sensitive2.txt
[root@vbox ~]# rm /mnt/secure_data/fichier_test
rm: remove regular file '/mnt/secure_data/fichier_test'? yes
[root@vbox ~]# cp /mnt/secure_data_snap/fichier_test /mnt/secure_data/
[root@vbox ~]# ls /mnt/secure_data
fichier_test  lost+found  sensitive1.txt  sensitive2.txt
```


3. **Optimiser l’espace disque** :


```bash
[root@vbox ~]# lvs
  LV          VG        Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  root        rl_vbox   -wi-ao----  <3.50g
  swap        rl_vbox   -wi-ao---- 512.00m
  secure_data vg_secure -wi-ao---- 500.00m
[root@vbox ~]# mount | grep /mnt/secure_data
/dev/mapper/vg_secure-secure_data on /mnt/secure_data type ext4 (rw,relatime,seclabel)
[root@vbox ~]# lvextend -L+200M /dev/vg_secure/secure_data
  Size of logical volume vg_secure/secure_data changed from 500.00 MiB (125 extents) to 700.00 MiB (175 extents).
  Logical volume vg_secure/secure_data successfully resized.
[root@vbox ~]# lvs
  LV          VG        Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  root        rl_vbox   -wi-ao----  <3.50g
  swap        rl_vbox   -wi-ao---- 512.00m
  secure_data vg_secure -wi-ao---- 700.00m
```




## __Étape 3 : Automatisation avec un script de sauvegarde__





1. **Créer un script `secure_backup.sh`** :


```bash
[root@vbox ~]# nano /usr/local/bin/secure_backup.sh
[root@vbox ~]# chmod +x /usr/local/bin/secure_backup.sh
[root@vbox ~]#
```


2. **Ajoutez une fonction de rotation des sauvegardes** :


```bash
find "$BACKUP_DIR" -name "secure_data_*.tar.gz" -type f -mtime +7 -exec rm -f {} \;
```


3. **Testez le script** :


```bash
[root@vbox ~]# /usr/local/bin/secure_backup.sh
tar: Removing leading `/' from member names
[root@vbox ~]# ls /backup/secure_data_*.tar.gz
/backup/secure_data_20241125.tar.gz
```


4. **Automatisez avec une tâche cron** :


```bash
0 3 * * * /usr/local/bin/secure_backup.sh
```




## __Étape 4 : Surveillance avancée avec `auditd`__






1. **Configurer auditd pour surveiller `/etc`** :


```bash
[root@vbox ~]# auditctl -w /etc -p wa -k etc_changes
Old style watch rules are slower
```


2. **Tester la surveillance** :


```bash
[root@vbox ~]# sudo touch /etc/test_audit
[root@vbox ~]# sudo echo "test modification" > /etc/test_audit
[root@vbox ~]# sudo rm /etc/test_audit
[root@vbox ~]# sudo ausearch -k etc-monitoring

time->Mon Nov 25 19:52:39 2024
type=PROCTITLE msg=audit(1732560759.803:204): proctitle=617564697463746C002D77002F657463002D70007761002D6B006574632D6D6F6E69746F72696E67
type=SOCKADDR msg=audit(1732560759.803:204): saddr=100000000000000000000000
type=SYSCALL msg=audit(1732560759.803:204): arch=c000003e syscall=44 success=yes exit=1076 a0=4 a1=7fff20211d20 a2=434 a3=0 items=0 ppid=2014 pid=2016 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="auditctl" exe="/usr/sbin/auditctl" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=CONFIG_CHANGE msg=audit(1732560759.803:204): auid=0 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key="etc-monitoring" list=4 res=1
[root@vbox ~]#
```


3. **Analyser les événements** :


```bash
[root@vbox ~]# sudo ausearch -k etc-monitoring

time->Mon Nov 25 19:52:39 2024
type=PROCTITLE msg=audit(1732560759.803:204): proctitle=617564697463746C002D77002F657463002D70007761002D6B006574632D6D6F6E69746F72696E67
type=SOCKADDR msg=audit(1732560759.803:204): saddr=100000000000000000000000
type=SYSCALL msg=audit(1732560759.803:204): arch=c000003e syscall=44 success=yes exit=1076 a0=4 a1=7fff20211d20 a2=434 a3=0 items=0 ppid=2014 pid=2016 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="auditctl" exe="/usr/sbin/auditctl" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=CONFIG_CHANGE msg=audit(1732560759.803:204): auid=0 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key="etc-monitoring" list=4 res=1

time->Mon Nov 25 19:55:15 2024
type=PROCTITLE msg=audit(1732560915.534:264): proctitle=617564697463746C002D77002F657463002D70007761002D6B006574632D6D6F6E69746F72696E67
type=SOCKADDR msg=audit(1732560915.534:264): saddr=100000000000000000000000
type=SYSCALL msg=audit(1732560915.534:264): arch=c000003e syscall=44 success=yes exit=1076 a0=4 a1=7ffe1fb1c7c0 a2=434 a3=0 items=0 ppid=2057 pid=2059 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="auditctl" exe="/usr/sbin/auditctl" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=CONFIG_CHANGE msg=audit(1732560915.534:264): auid=0 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key="etc-monitoring" list=4 res=0

[root@vbox ~]# sudo ausearch -k etc-monitoring > /var/log/audit_etc.log
[root@vbox ~]# cat /var/log/audit_etc.log

time->Mon Nov 25 19:52:39 2024
type=PROCTITLE msg=audit(1732560759.803:204): proctitle=617564697463746C002D77002F657463002D70007761002D6B006574632D6D6F6E69746F72696E67
type=SOCKADDR msg=audit(1732560759.803:204): saddr=100000000000000000000000
type=SYSCALL msg=audit(1732560759.803:204): arch=c000003e syscall=44 success=yes exit=1076 a0=4 a1=7fff20211d20 a2=434 a3=0 items=0 ppid=2014 pid=2016 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="auditctl" exe="/usr/sbin/auditctl" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=CONFIG_CHANGE msg=audit(1732560759.803:204): auid=0 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key="etc-monitoring" list=4 res=1

time->Mon Nov 25 19:55:15 2024
type=PROCTITLE msg=audit(1732560915.534:264): proctitle=617564697463746C002D77002F657463002D70007761002D6B006574632D6D6F6E69746F72696E67
type=SOCKADDR msg=audit(1732560915.534:264): saddr=100000000000000000000000
type=SYSCALL msg=audit(1732560915.534:264): arch=c000003e syscall=44 success=yes exit=1076 a0=4 a1=7ffe1fb1c7c0 a2=434 a3=0 items=0 ppid=2057 pid=2059 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="auditctl" exe="/usr/sbin/auditctl" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=CONFIG_CHANGE msg=audit(1732560915.534:264): auid=0 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key="etc-monitoring" list=4 res=0
[root@vbox ~]#
```




## Étape 5 : Sécurisation avec Firewalld





1. **Configurer un pare-feu pour SSH et HTTP/HTTPS uniquement** :

```bash
[root@vbox ~]# sudo firewall-cmd --list-all
public (active)
  target: DROP
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources:
  services: cockpit dhcpv6-client http https ssh
  ports: 2222/tcp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
[root@vbox ~]#
```

2. **Bloquer des IP suspectes** :

```bash
[root@vbox ~]# sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.1.100" drop' --permanent
success
[root@vbox ~]# sudo firewall-cmd --list-rich-rules

[root@vbox ~]# sudo firewall-cmd --reload
success
[root@vbox ~]#
```

3. **Restreindre SSH à un sous-réseau spécifique** :

```bash
[root@vbox ~]# sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.1.100" drop' --permanent
success
[root@vbox ~]# sudo firewall-cmd --list-rich-rules

[root@vbox ~]# sudo firewall-cmd --reload
success
[root@vbox ~]# sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept' --permanent
success
[root@vbox ~]# sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" service name="ssh" drop' --permanent
success
[root@vbox ~]# sudo firewall-cmd --reload
success
[root@vbox ~]#
[root@vbox ~]# sudo firewall-cmd --list-rich-rules
rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept
rule family="ipv4" source address="192.168.1.100" drop
rule family="ipv4" service name="ssh" drop
```