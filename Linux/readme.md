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
- [Shell Style](#shell-style)
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
  * [Grep and Ack](#grep-and-ack)
  * [Processes and Networks](#processes-and-networks)
  * [Files](#files)
  * [Bash Tips](#bash-tips)
- [macOS](#macOS)
  * [Reading .plist files](#Reading-.plist-files)
  * [Quarantine Events](#Quarantine-Events)
  * [Install History](Install-History)
  * [Most Recently Used (MRU)](#Most-Recently-Used-(MRU))
  * [Audit Logs](#Audit-Logs)
  * [Command line history](#Command-line-history)
  * [WHOMST is in the Admin group](#WHOMST-is-in-the-Admin-group) 
  * [Persistence locations](#Persistence-locations) 
  * [Transparency, Consent, and Control (TCC)](#Transparency,-Consent,-and-Control-(TCC))
  * [Built-In Security Mechanisms](#Built-In-Security-Mechanisms)
- [Malware](#Malware)
  * [Rapid Malware Analysis](#rapid-malware-Analysis)
  * [Unquarantine Malware](#Unquarantine-Malware)
  * [Process Monitor](#process-monitor)
  * [Hash Check Malware](#hash-check-malware)
  * [Decoding Powershell](#decoding-powershell)
- [SOC](#SOC)
  * [Sigma Converter](#sigma-converter)
  * [SOC Prime](#soc-prime)
- [Honeypots](#honeypots)
  * [Basic Honeypots](#basic-honeypots) 
- [Network Traffic](#network-traffic)
  * [Capture Traffic](#capture-traffic)
  * [TShark](#tshark)
  * [Extracting Stuff](#extracting-stuff)
  * [PCAP Analysis IRL](#pcap-analysis-irl)
- [Digital Forensics](#Digital-Forensics) 
  * [Volatility](#volatility)
  * [Quick Forensics](#quick-forensics)
  * [Chainsaw](#chainsaw)
  * [Browser History](#browser-history)
  * [Which logs to pull in an incident](#Which-logs-to-pull-in-an-incident)
  * [USBs](#USBs)
  * [Reg Ripper](#reg-ripper)
  * [Winget](#winget)

---

As you scroll along, it's easy to lose orientation. Wherever you are in the Blue Team Notes, if you look to the top-left of the readme you'll see a little icon. This is a small table of contents, and it will help you figure out where you are, where you've been, and where you're going

![image](https://user-images.githubusercontent.com/44196051/122612244-b834fd00-d07a-11eb-9281-e4d93f4f6059.png)

As you go through sections, you may notice the arrowhead that says 'section contents'. I have nestled the sub-headings in these, to make life a bit easier.

![image](https://user-images.githubusercontent.com/44196051/124335025-d4fc2500-db90-11eb-86cc-80fc8db2c193.png)

---

# Shell Style

<details>
    <summary>section contents</summary>

  + [Give shell timestamp](#give-shell-timestamp)
    - [CMD](#cmd)
    - [Pwsh](#pwsh)
    - [Bash](#bash)

</details>

### Give shell timestamp
For screenshots during IR, I like to have the date, time, and sometimes the timezone in my shell
#### CMD
```bat
setx prompt $D$S$T$H$H$H$S$B$S$P$_--$g
:: all the H's are to backspace the stupid microsecond timestamp
:: $_ and --$g seperate the date/time and path from the actual shell
:: We make the use of the prompt command: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/prompt
:: setx is in fact the command line command to write variables to the registery
:: We are writing the prompt's new timestamp value in the cmd line into the reg so it stays, otherwise it would not stay in the cmdline when we closed it.
```
