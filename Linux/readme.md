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
  * [Command "uptime"](#command-uptime)
  * [Command "uname"](#command-uname)
  * [Command "free"](#command-free)
  * [Command "df"](#command-df)
  * [Command "fdisk"](#command-fdisk)
  * ["proc" directory](#proc-directory)
- [ACCOUNT INFORMATION](#account-information)



---

The following commands have been performed on a fresh Kali VM installation

---

# SYSTEM INFORMATION

---

# Command "hostname"
Command used to obtain the machine hostname
```bat
hostname -s
kali
```

# Command "date"
Command used to obtain the machine date and time. "-u" for UTC time
```bat
date -u
Thu Jun 20 03:31:58 PM UTC 2024
```

# Command "uptime"
Command used to display how long the machine has been running, number of logged on users and system load average for the last 1, 5 and 15 minutes.
```bat
uptime   
11:35:05 up 21 min,  1 user,  load average: 0.20, 0.09, 0.08
```

# Command "uname"
Command used to get system information. "-a" will display all available information
```bat
uname -a
Linux kali 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.6.15-2kali1 (2024-05-17) x86_64 GNU/Linux
```

# Command "free"
Command used to display the amount of free/used physical and swap memory of the machine. Using "-h" option for human readable format
```bat
free -h
               total        used        free      shared  buff/cache   available
Mem:           1.9Gi       927Mi       608Mi        11Mi       593Mi       1.0Gi
Swap:          1.0Gi          0B       1.0Gi
```

# Command "df"
Command used to display system usage. "-a" for all info and "-h" for human readable
```bat
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
cgroup2            0     0     0    - /sys/fs/cgroup
pstore             0     0     0    - /sys/fs/pstore
bpf                0     0     0    - /sys/fs/bpf
systemd-1          -     -     -    - /proc/sys/fs/binfmt_misc
hugetlbfs          0     0     0    - /dev/hugepages
mqueue             0     0     0    - /dev/mqueue
tracefs            0     0     0    - /sys/kernel/tracing
debugfs            0     0     0    - /sys/kernel/debug
configfs           0     0     0    - /sys/kernel/config
fusectl            0     0     0    - /sys/fs/fuse/connections
binfmt_misc        0     0     0    - /proc/sys/fs/binfmt_misc
sunrpc             0     0     0    - /run/rpc_pipefs
tmpfs           198M  124K  198M   1% /run/user/1000
gvfsd-fuse      0.0K  0.0K  0.0K    - /run/user/1000/gvfs
portal          0.0K  0.0K  0.0K    - /run/user/1000/doc
```

# Command "fdisk"
Command used to display partition table information. "-l" for associated info
```bat
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
```bat
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
