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
- [Windows](#Windows)
  * [OS Queries](#os-queries)
  * [Account Queries](#account-queries)
  * [Service Queries](#service-queries)
  * [Network Queries](#network-queries)
  * [Remoting Queries](#remoting-queries)
  * [Firewall Queries](#firewall-queries)
  * [SMB Queries](#smb-queries)
  * [Process Queries](#process-queries)
  * [Recurring Task Queries](#recurring-task-queries)
  * [File Queries](#file-queries)
  * [Registry Queries](#registry-queries)
  * [Driver Queries](#driver-queries)
  * [DLL Queries](#dll-queries)
  * [AV Queries](#AV-Queries)
  * [Log Queries](#log-queries)
  * [Powershell Tips](#powershell-tips)
- [Linux](#linux)
  * [Bash History](#bash-history)


---

The following commands have been performed on a Kali VM

---

# Command "hostname"
Command used to obtain the machine hostname
```bat
hostname -s
kali
```
