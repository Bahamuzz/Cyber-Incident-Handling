<p align="center">
  <img width="450" height="450" src="https://github.com/Bahamuzz/Cyber-Incident-Handling/assets/125216460/f65a6889-a140-4ea2-b97d-9a1369380a3e">
</p>

# Linux Incident handling notes
Personal notes for Linux Incident Handling

## Intrusion handling and incident response Frameworks
Most common are:
- Cyber Kill Chain (https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- Diamond model

But the most common used is the NIST SP 800-61 revision 2 (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf). For this, phases of an incident are:

![image](https://github.com/Bahamuzz/Cyber-Incident-Handling/assets/125216460/bc33a772-7a80-424b-a63a-03b274788ee5)

The incident response process has several phases. The **initial phase** involves establishing and training an incident response team, and acquiring the necessary tools and resources. **During preparation**, the organization also attempts to limit the number of incidents that will occur by selecting and implementing a set of controls based on the results of risk assessments. However, residual risk will inevitably persist after controls are implemented. **Detection** of security breaches is thus necessary to alert the organization whenever incidents occur. In keeping with the severity of the incident, the organization can mitigate the impact of the incident by **containing** it and ultimately recovering from it. **During this phase**, activity often cycles back to detection and analysis—for example, to see if additional hosts are infected by malware while eradicating a malware incident. **After the incident is adequately handled**, the organization issues a report that details the cause and cost of the incident and the steps the organization should take to prevent future incidents. This section describes the major phases of the incident response process—preparation, detection and analysis, containment, eradication and recovery, and post-incident activity—in detail.



## Table of Contents
- [SYSTEM INFORMATION](#system-information)
  * [Command "hostname"](#command-hostname)
  * [Command "date"](#command-date)
  * [Command "timedatectl"](#command-timedatectl)
  * [Command "uptime"](#command-uptime)
  * [Command "uname"](#command-uname)
  * [Command "free"](#command-free)
  * [Command "df"](#command-df)
  * [Command "fdisk"](#command-fdisk)
  * ["proc" directory](#proc-directory)
- [ACCOUNT INFORMATION](#account-information)
  * [Command "w"](#command-w)
  * [Command "who"](#command-who)
  * [Command "last"](#command-last)
  * [Command "faillog"](#command-faillog)
  * [Shadow file](#shadow-file)
  * [Group file](#group-file)
  * [Sudoers file](#sudoers-file)
  * [Command "history"](#command-history)
- [NETWORK INFORMATION](#network-information)
  * [Command "ifconfig"](#command-ifconfig)
  * [Command "netstat"](#command-netstat)
  * [Command "route"](#command-route)
  * [Command "arp"](#command-arp)
  * [Command "lsof--i"](#command-lsof--i)
  * [Command "iptables"](#command-iptables)
- [PROCESSES AND SERVICES](#processes-and-services)
  * [Command "ps"](#command-ps)
  * [Command "top"](#command-top)
  * [Command "service"](#command-service)
  * [Command "systemctl"](#command-systemctl)
  * [Command "lsmod"](#command-lsmod)
  * [Command "lsof"](#command-lsof)
  * [Command "ls"](#command-ls)
  * [Command "less"](#command-less)
- [AUTORUN AND AUTOLOAD INFORMATION](#autorun-and-autoload-information)
  * [Command "crontab"](#command-crontab)


---

The following commands have been performed on a fresh Kali VM installation

---

# SYSTEM INFORMATION

---

# Command "hostname"
Command used to obtain the machine hostname
```bash
hostname -s
kali
```

# Command "date"
Command used to obtain the machine date and time. "-u" for UTC time
```bash
date -u
Thu Jun 20 03:31:58 PM UTC 2024
```

# Command "timedatectl"
Command used to query and change the system clock and its settings
```bash
timedatectl
               Local time: Fri 2024-06-21 10:31:47 EDT
           Universal time: Fri 2024-06-21 14:31:47 UTC
                 RTC time: Tue 2024-06-18 07:51:14
                Time zone: America/New_York (EDT, -0400)
System clock synchronized: no
              NTP service: inactive
          RTC in local TZ: no
```

# Command "uptime"
Command used to display how long the machine has been running, number of logged on users and system load average for the last 1, 5 and 15 minutes.
```bash
uptime   
11:35:05 up 21 min,  1 user,  load average: 0.20, 0.09, 0.08
```

# Command "uname"
Command used to get system information. "-a" will display all available information
```bash
uname -a
Linux kali 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.6.15-2kali1 (2024-05-17) x86_64 GNU/Linux
```

# Command "free"
Command used to display the amount of free/used physical and swap memory of the machine. Using "-h" option for human readable format
```bash
free -h
               total        used        free      shared  buff/cache   available
Mem:           1.9Gi       927Mi       608Mi        11Mi       593Mi       1.0Gi
Swap:          1.0Gi          0B       1.0Gi
```

# Command "df"
Command used to display system usage. "-a" for all info and "-h" for human readable
```bash
df -ah
Filesystem      Size  Used Avail Use% Mounted on
sysfs              0     0     0    - /sys
proc               0     0     0    - /proc
udev            948M     0  948M   0% /dev
devpts             0     0     0    - /dev/pts
tmpfs           198M 1016K  197M   1% /run
/dev/sda1        79G   15G   61G  20% /
securityfs         0     0     0    - /sys/kernel/security
tmpfs           989M     0  989M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
```

# Command "fdisk"
Command used to display partition table information. "-l" for associated info
```bash
Disk /dev/sda: 80.09 GiB, 86000000000 bytes, 167968750 sectors
Disk model: VBOX HARDDISK   
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xc3a874f6

Device     Boot Start       End   Sectors  Size Id Type
/dev/sda1  *     2048 167968749 167966702 80.1G 83 Linux
```

# "proc" directory
There are plenty of files on "/proc" directory in which we can find system information. Some useful examples are:
```bash
cat /proc/partitions 
major minor  #blocks  name

  11        0    1048575 sr0
   8        0   83984375 sda
   8        1   83983351 sda1
```

---

# ACCOUNT INFORMATION

---

# Command "w"
Command used to display details about currently logged on users
```bash
w
 11:55:56 up 42 min,  1 user,  load average: 0.08, 0.08, 0.08
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
kali              -                Tue02    2days  0.00s  0.03s lightdm --session-child 13 24
```

# Command "who"
Alternative to "w" command
```bash
who     
kali     tty7         2024-06-18 02:41 (:0)
kali     pts/1        2024-06-20 11:45
```

# Command "last"
Command used to display information about the last logged-in users. "tail -20" will display last 20 attempts
```bash
last | tail -20

kali     tty7         :0               Tue Jun 18 02:41    gone - no logout
reboot   system boot  6.6.15-amd64     Tue Jun 18 02:39   still running
kali     tty7         :0               Sat Jun  8 17:09 - 02:15 (1+09:05)
reboot   system boot  6.6.15-amd64     Sat Jun  8 17:09 - 02:15 (1+09:05)

wtmp begins Sat Jun  8 17:09:14 2024
```

# Command "faillog"
Command used to display formatted information of the failure log from /var/log/faillog
```bash
faillog -a
Login       Failures Maximum Latest                   On

root            0        0   12/31/69 19:00:00 -0500
```

# Shadow file
File that list all the local users
```bash
cut -d: -f1 /etc/shadow
user1
user2
```

# Group file
File that list all the local groups
```bash
cut -d: -f1 /etc/group
group1
group2
```

# Sudoers file
Is a configuration file used by the sudo command, which allows a permitted user to execute a command as another user (typically the superuser, or root)
```bash
cat /etc/sudoers
```

# Command "history"
Command used to review the commands used previously. If reviewing from non-root, only will see the history of that user.
```bash
history       
    1  apt-get update
    2  apt-get upgrade
```

---

# NETWORK INFORMATION

---

# Command "ifconfig"
Command used to get status information about a host´s interface configuration
```bash
ifconfig -a
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet x.x.x.x  netmask x.x.x.x  broadcast x.x.x.x
        inet6 x::x:x:x:x  prefixlen 64  scopeid 0x20<link>
        ether x:x:x:x:x:x  txqueuelen 1000  (Ethernet)
        RX packets 434  bytes 197828 (193.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 403  bytes 39722 (38.7 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

# Command "netstat"
Command used to display the contents of various network-related data structures for active connections. "-antup" connectors for the following format, "plantux" for all unix.
```bash
netstat -antup
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
udp        0      0 x.x.x.x:x            x.x.x.x:x             ESTABLISHED 614/NetworkManager
```

Also the following one to check in real time active connections:
```bash
netstat -antup
netstat --inet -ap
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 localhost:1234          localhost:54458         ESTABLISHED 1643/nc             
tcp        0      0 localhost:54458         localhost:1234          ESTABLISHED 1663/nc
```

# Command "route"
Command used to show/manipulate the IP routing table
```bash
route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         10.0.2.2        0.0.0.0         UG    100    0        0 eth0
10.0.2.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0
```

# Command "arp"
Command used to show/manipulate the system ARP cache
```bash
arp -a
? (10.0.2.2) at 52:54:00:12:35:02 [ether] on eth0
```

# Command "lsof -i"
Command used to show list of processes on open ports
```bash
lsof -i
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
NetworkMa 593 root   26u  IPv4   7256      0t0  UDP 10.0.2.15:bootpc->10.0.2.2:bootps 
```

# Command "iptables"
Command used to check the firewall iptables status. "-L -v" for list all rules with verbose
```bash
iptables -L -v 
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination   
```

---

# PROCESSES AND SERVICES

---

# Command "ps"
Command used to display information about system processes. "aux" to display in-depth details
```bash
ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.6  22640 13172 ?        Ss   08:23   0:00 /sbin/init splash
root           2  0.0  0.0      0     0 ?        S    08:23   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        S    08:23   0:00 [pool_workqueue_release]
root           4  0.0  0.0      0     0 ?        I<   08:23   0:00 [kworker/R-rcu_g]
```

Also you can use "ps -ef --forest" to display it in a tree view:
```bash
ps -ef --forest
UID          PID    PPID  C STIME TTY          TIME CMD
root           2       0  0 08:54 ?        00:00:00 [kthreadd]
root           3       2  0 08:54 ?        00:00:00  \_ [rcu_gp]
remnux      1472     864  0 08:54 ?        00:00:04  \_ /usr/libexec/gnome-terminal-server
remnux      1496    1472  0 08:54 pts/0    00:00:00  |   \_ bash
root        2827    1496  0 08:59 pts/0    00:00:00  |       \_ sudo su
root        2828    2827  0 08:59 pts/0    00:00:00  |           \_ su
root        2829    2828  0 08:59 pts/0    00:00:00  |               \_ bash
root        6997    2829  0 11:33 pts/0    00:00:00  |                   \_ ps -ef --forest
```

# Command "top"
Command used to show additional info about the current running processes
```bash
top           
top - 08:40:21 up 16 min,  1 user,  load average: 0.00, 0.05, 0.07
Tasks: 173 total,   1 running, 172 sleeping,   0 stopped,   0 zombie
%Cpu(s):  1.1 us,  1.0 sy,  0.0 ni, 97.9 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st 
MiB Mem :   1976.7 total,    406.2 free,    975.7 used,    760.4 buff/cache     
MiB Swap:   1024.0 total,   1024.0 free,      0.0 used.   1001.1 avail Mem 

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                                                                                                                               
    748 root      20   0  404300 125776  57736 S   2.3   6.2   0:09.01 Xorg
   1180 kali      20   0  460004 104544  88352 S   1.0   5.2   0:05.04 qterminal
    251 root      20   0       0      0      0 I   0.3   0.0   0:00.11 kworker/0:3-events
```

# Command "service"
Command used to provide the status of each service using "--status-all
```bash
service --status-all
 [ - ]  apache-htcacheclean
 [ - ]  apache2
 [ - ]  apparmor
 [ - ]  atftpd
 [ - ]  bluetooth
 [ - ]  console-setup.sh
 [ + ]  cron
```

# Command "systemctl"
Another command to display a list of system services and the associated state. "systemctl list-units --type=service --state=running --no-legend" for current running processes
```bash
systemctl list-units --type=service --state=running --no-legend 
  UNIT                           LOAD   ACTIVE SUB     DESCRIPTION                                   
  accounts-daemon.service        loaded active running Accounts Service
  colord.service                 loaded active running Manage, Install and Generate Color Profiles
  cron.service                   loaded active running Regular background program processing daemon
  dbus.service                   loaded active running D-Bus System Message Bus
```

# Command "lsmod"
Command used to show the status of modules in the Linux Kernel
```bash
lsmod  
Module                  Size  Used by
snd_seq_dummy          12288  0
snd_hrtimer            12288  1
snd_seq               114688  7 snd_seq_dummy
snd_seq_device         16384  1 snd_seq
rfkill                 40960  2
qrtr                   57344  4
vboxsf                 49152  0
```

# Command "lsof"
Command used to list open files. "-c <PROCESS NAME>" to list open files on specific process:
```bash
lsof -c cron
COMMAND PID USER   FD   TYPE             DEVICE SIZE/OFF    NODE NAME
cron    604 root  cwd    DIR                8,1     4096 2490640 /var/spool/cron
cron    604 root  rtd    DIR                8,1     4096       2 /
cron    604 root  txt    REG                8,1    60064 4456874 /usr/sbin/cron
```

Command "lsof -nPi | cut -f 1 -d " "| uniq | tail -n +2" to list open files using the network:
```bash
lsof -nPi | cut -f 1 -d " "| uniq | tail -n +2
NetworkMa
```

Command "-p <PID>" to list open files by specific PID 
```bash
lsof -p 604                                   
COMMAND PID USER   FD   TYPE             DEVICE SIZE/OFF    NODE NAME
cron    604 root  cwd    DIR                8,1     4096 2490640 /var/spool/cron
cron    604 root  rtd    DIR                8,1     4096       2 /
cron    604 root  txt    REG                8,1    60064 4456874 /usr/sbin/cron
cron    604 root  mem    REG                8,1  3052896 4759752 /usr/lib/locale/locale-archive
cron    604 root  mem    REG                8,1    30632 4632772 /usr/lib/x86_64-linux-gnu/libcap-ng.so.0.0.0
```

# Command "ls"
Command used to the files of a directory. "-al /proc/<PID>/exe" to get the path of suspicious process PID:
```bash
ls -al /proc/604/exe 
lrwxrwxrwx 1 root root 0 Jun 26 08:23 /proc/604/exe -> /usr/sbin/cron
```

# Command "less"
Command used to monitor logs in real time, with option "+F /var/log/filename"
```bash
less +F /var/log/messages
```

---

# AUTORUN AND AUTOLOAD INFORMATION

---

# Command "crontab"
Crontab can be used to review or schedule specific commands/tasks execution in Linux. To list all cron jobs will use "-l"
```bash
# crontab -l
# Edit this file to introduce tasks to be run by cron.
10 5 1 * * ls /var/log/ 
```

With option "-u root -l" will list cron jobs by root and other UID 0 accounts:
```bash
# crontab -u root -l
# Edit this file to introduce tasks to be run by cron.
10 5 1 * * ls /var/log/ 
```

Command "cat /etc/crontab" and "ls /etc/cron.*" to spot unusual cron jobs
