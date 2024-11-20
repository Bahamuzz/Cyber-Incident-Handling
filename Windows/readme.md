<p align="center">
  <img width="450" height="450" src="https://github.com/Bahamuzz/Cyber-Incident-Handling/assets/125216460/f65a6889-a140-4ea2-b97d-9a1369380a3e">
</p>

# Windows Incident response notes
Personal notes for Windows Incident response

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
  * [Command "systeminfo"](#command-systeminfo)
- [ACCOUNT INFORMATION](#account-information)
  * [Command "net user"](#command-net-user)
  * [Command "net localgroup"](#command-net-localgroup)
- [NETWORK INFORMATION](#network-information)
  * [Command "ipconfig"](#command-ipconfig)
  * [Command "netstat"](#command-netstat)
  * [Command "net view"](#command-net-view)
  * [Command "net session"](#command-net-session)
  * [Command "net use"](#command-net-use)
- [AUTORUN, TASK, PROCESSES AND SERVICES](#autorun-task-processes-and-services)
  * [Command "schtasks"](#command-schtasks)
  * [Command "tasklist"](#command-tasklist)
  * [Command "wmic process"](#command-wmic-process)
  * [Command "wmic startup"](#command-wmic-startup)
  * [Command "wmic service"](#command-wmic-service)
  * [Command "reg query"](#command-reg-query)


---

The following commands have been performed on a fresh Windows 11 VM installation

---

# SYSTEM INFORMATION

---

# Command "hostname"
Command used to obtain the machine hostname
```powershell
hostname
DESKTOP-O5LIVH3
```

# Command "date"
Command used to obtain the machine date and time. Parameters "-date (Get-Date).ToUniversalTime()" for UTC time
```powershell
date -date (Get-Date).ToUniversalTime()

Friday, November 15, 2024 2:54:49 PM
```

# Command "systeminfo"
Command used to query information about the host.
```powershell
systeminfo

Host Name:                 DESKTOP-O5LIVH3
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19045 N/A Build 19045
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          testuser
Registered Organization:
Product ID:                00330-80000-00000-AA968
Original Install Date:     11/15/2024, 6:39:45 AM
System Boot Time:          11/15/2024, 6:47:45 AM
System Manufacturer:       innotek GmbH
System Model:              VirtualBox
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 186 Stepping 3 GenuineIntel ~2611 Mhz
BIOS Version:              innotek GmbH VirtualBox, 12/1/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              es;Spanish (Traditional Sort)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,048 MB
Available Physical Memory: 696 MB
Virtual Memory: Max Size:  3,200 MB
Virtual Memory: Available: 1,744 MB
Virtual Memory: In Use:    1,456 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\DESKTOP-O5LIVH3
Hotfix(s):                 5 Hotfix(s) Installed.
                           [01]: KB5031988
                           [02]: KB5015684
                           [03]: KB5033372
                           [04]: KB5014032
                           [05]: KB5032907
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Desktop Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.0.2.2
                                 IP address(es)
                                 [01]: 10.0.2.15
                                 [02]: fe80::5e6:c588:576c:396d
```

---

# ACCOUNT INFORMATION

---

# Command "net user"
Command used to display current local users.
```powershel
net user

User accounts for \\DESKTOP-O5LIVH3

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
testuser                 WDAGUtilityAccount
```

# Command "net localgroup"
Command used to get information about local host groups.
```powershell
net localgroup

Aliases for \\DESKTOP-O5LIVH3

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Cryptographic Operators
*Device Owners
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Remote Management Users
*Replicator
*System Managed Accounts Group
*Users
```

---

# NETWORK INFORMATION

---

# Command "ipconfig"
Command used to get status information about a host´s interface configuration. Use "/all" for extended info details.
```powershell
ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-O5LIVH3
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Desktop Adapter
   Physical Address. . . . . . . . . : 08-00-27-43-33-26
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::5e6:c588:576c:396d%6(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.0.2.15(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Sunday, November 17, 2024 11:37:04 PM
   Lease Expires . . . . . . . . . . : Monday, November 18, 2024 11:41:45 PM
   Default Gateway . . . . . . . . . : 10.0.2.2
   DHCP Server . . . . . . . . . . . : 10.0.2.2
   DHCPv6 IAID . . . . . . . . . . . : 101187623
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2E-C9-93-C9-08-00-27-43-33-26
   DNS Servers . . . . . . . . . . . : 10.103.21.230
                                       10.103.21.231
                                       212.166.132.110
                                       212.166.132.104
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

# Command "netstat"
Command used to display the contents of various network-related data structures for active connections. "-naob" connectors for the following format.
```powershell
netstat -naob

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       880
  RpcSs
 [svchost.exe]
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
 Can not obtain ownership information
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       1152
  CDPSvc
 [svchost.exe]
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       660
 [lsass.exe]
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       508
 Can not obtain ownership information
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       364
  EventLog
 [svchost.exe]
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       388
  Schedule
 [svchost.exe]
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       1880
 [spoolsv.exe]
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       644
```

# Command "net view"
Command used to display file share status on the local machine.
```powershell
net view \\localhost
There are no entries in the list.
```

# Command "net session"
Command used to check if there is any SMB or NetBIOS connections established to machine´s network shares.
```powershell
net session
There are no entries in the list.
```

# Command "net use"
Command used to check sessions originating from your host machine.
```powershell
net use
New connections will be remembered.

There are no entries in the list.
```

---

# AUTORUN, TASK, PROCESSES AND SERVICES

---

# Command "schtasks"
Command used to display information about system scheduled tasks. Use "/FO table" for output in format table.
```powershell
SCHTASKS /FO table

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
MicrosoftEdgeUpdateTaskMachineCore       11/18/2024 4:14:07 PM  Ready
MicrosoftEdgeUpdateTaskMachineUA         11/18/2024 7:44:07 AM  Ready
OneDrive Reporting Task-S-1-5-21-3910765 11/18/2024 7:46:13 AM  Ready
OneDrive Standalone Update Task-S-1-5-21 11/19/2024 7:05:03 AM  Ready
```

# Command "tasklist"
Command used to show current running processes on the system. Option "/v" for verbose. Also "/SVC" to check associated services to processes. Also "tasklist /fi "pid eq 840" /V" For verbose filtering by PID.
```powershell
tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0        136 K
Registry                        92 Services                   0     31,364 K
smss.exe                       336 Services                   0        964 K
csrss.exe                      436 Services                   0      4,728 K
wininit.exe                    508 Services                   0      6,328 K
csrss.exe                      516 Console                    1      3,312 K
```

# Command "wmic process"
If we want to analyze further a specific process ID seen on tasklist, we can do it with "wmic process" command, filtering by the following:
```powershell
wmic process where ProcessId=2592 list full


CommandLine="ctfmon.exe"
CSName=DESKTOP-O5LIVH3
Description=ctfmon.exe
ExecutablePath=C:\Windows\system32\ctfmon.exe
ExecutionState=
Handle=2592
HandleCount=416
InstallDate=
KernelModeTime=781250
MaximumWorkingSetSize=1380
MinimumWorkingSetSize=200
Name=ctfmon.exe
OSName=Microsoft Windows 10 Pro|C:\Windows|\Device\Harddisk0\Partition2
OtherOperationCount=988
OtherTransferCount=3024
PageFaults=5579
PageFileUsage=3792
ParentProcessId=1032
PeakPageFileUsage=3856
PeakVirtualSize=2203462483968
PeakWorkingSetSize=20152
Priority=13
PrivatePageCount=3883008
ProcessId=2592
QuotaNonPagedPoolUsage=16
QuotaPagedPoolUsage=193
QuotaPeakNonPagedPoolUsage=17
QuotaPeakPagedPoolUsage=195
ReadOperationCount=0
ReadTransferCount=0
SessionId=1
Status=
TerminationDate=
ThreadCount=9
UserModeTime=937500
VirtualSize=2203457953792
WindowsVersion=10.0.19045
WorkingSetSize=19062784
WriteOperationCount=0
WriteTransferCount=0
```

If we want to filter by specific fields:
```powershell
wmic process where processid=2592 get name,processid,executablepath,commandline
CommandLine   ExecutablePath                  Name        ProcessId
"ctfmon.exe"  C:\Windows\system32\ctfmon.exe  ctfmon.exe  2592
```

# Command "wmic startup"
Will display info about processes configured to be run on Windows boot. Using "list brief" for short answer and "list full" for verbose.
```powershell
wmic startup list brief
Caption                                                   Command                                                                                                 User
MicrosoftEdgeAutoLaunch_DCC7F3E742907DE2B0F8468B0BE79833  "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start  DESKTOP-O5LIVH3\testuser
OneDrive                                                  "C:\Users\testuser\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background                           DESKTOP-O5LIVH3\testuser
SecurityHealth                                            %windir%\system32\SecurityHealthSystray.exe                                                             Public
VBoxTray                                                  %SystemRoot%\system32\VBoxTray.exe                                                                      Public
```

# Command "wmic service"
Command used to show info about services on host. Using "list brief" for short answer and "list full" for verbose.
```powershell
wmic service where "State='Running'" get Name,ProcessID,StartMode,State,Status
Name                    ProcessId  StartMode  State    Status
Appinfo                 444        Manual     Running  OK
AppXSvc                 2368       Manual     Running  OK
AudioEndpointBuilder    1052       Auto       Running  OK
Audiosrv                1560       Auto       Running  OK
BFE                     1864       Auto       Running  OK
BrokerInfrastructure    764        Auto       Running  OK
camsvc                  1724       Manual     Running  OK
CDPSvc                  1184       Auto       Running  OK
ClipSVC                 2368       Manual     Running  OK
CoreMessagingRegistrar  860        Auto       Running  OK
CryptSvc                1284       Auto       Running  OK
```

# Command "reg query"
Command used to check registry for startup folder configured processes. Also can be run against "RunOnce".
```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    MicrosoftEdgeAutoLaunch_DCC7F3E742907DE2B0F8468B0BE79833    REG_SZ    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start
    OneDrive    REG_SZ    "C:\Users\testuser\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
```
