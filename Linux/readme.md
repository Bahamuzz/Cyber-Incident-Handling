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
- [Command "hostname"](#command-hostname)
- [Command "date"](#command-date)
- [Command "uptime"](#command-uptime)
- [Command "uname"](#command-uname)
- [Command "free"](#command-free)



---

The following commands have been performed on a Kali VM

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
