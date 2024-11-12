# ----------------------------------------------
# Script Name :    laner.py
# Description :    Script to gather most common info on Linux systems when handling an incident. Linux ANalizER
# Author      :    Rubén Vergara
# Date        :    2024-11-12
# Version     :    1.0
# Python Ver. :    3.x
# ----------------------------------------------

import subprocess

host = subprocess.getoutput('hostname')
date = subprocess.getoutput('date -u')
uname = subprocess.getoutput('uname -a')
uptime = subprocess.getoutput('uptime -p')
free = subprocess.getoutput('free -h')
df = subprocess.getoutput('df -ah')
fdisk = subprocess.getoutput('fdisk -l')
who = subprocess.getoutput('who')
last = subprocess.getoutput('last -10 | head -10')
ifconfig = subprocess.getoutput('ifconfig -a')
route = subprocess.getoutput('route | grep -v "Kernel IP routing table"')
arp = subprocess.getoutput('arp -a')
services = subprocess.getoutput('service --status-all')
netstat = subprocess.getoutput('netstat -antup')
ps = subprocess.getoutput('ps -ef --forest')
crontab = subprocess.getoutput('crontab -l')



print ("\033[33;42m################################################\033[0m")
print ("\033[33;42m#              HOST INFO                       #\033[0m")
print ("\033[33;42m################################################\033[0m")
print ('Hostname :',host)
print ('Date     :',date)
print ('Sysinfo  :',uname)
print ('Uptime   :',uptime)
print ('')
print ("\033[33;42m################################################\033[0m")
print ("\033[33;42m#             MEMORY INFO                      #\033[0m")
print ("\033[33;42m################################################\033[0m")
print (free)
print ('')
print ("\033[33;42m################################################\033[0m")
print ("\033[33;42m#           SYSTEM USAGE INFO                  #\033[0m")
print ("\033[33;42m################################################\033[0m")
print (df)
print ('')
print ("\033[33;42m################################################\033[0m")
print ("\033[33;42m#            PARTITIONS INFO                   #\033[0m")
print ("\033[33;42m################################################\033[0m")
print (fdisk)
print ('')
print ("\033[33;42m################################################\033[0m")
print ("\033[33;42m#               LOGIN INFO                     #\033[0m")
print ("\033[33;42m################################################\033[0m")
print ('Currently logged users :')
print (who)
print ('')
print ('Last 10 logins :')
print (last)
print ('')
print ("\033[33;42m################################################\033[0m")
print ("\033[33;42m#              NETWORK INFO                    #\033[0m")
print ("\033[33;42m################################################\033[0m")
print ('Interfaces configuration:')
print (ifconfig)
print ('')
print ('Routing table :')
print (route)
print ('')
print ('ARP Cache :')
print (arp)
print ('')
print ("\033[33;42m################################################\033[0m")
print ("\033[33;42m#              SERVICES INFO                   #\033[0m")
print ("\033[33;42m################################################\033[0m")
print (services)
print ('')
print ("\033[33;42m################################################\033[0m")
print ("\033[33;42m#               PROCESS INFO                   #\033[0m")
print ("\033[33;42m################################################\033[0m")
print (ps)
print ('')
print ("\033[33;42m################################################\033[0m")
print ("\033[33;42m#             CONNECTIONS INFO                 #\033[0m")
print ("\033[33;42m################################################\033[0m")
print (netstat)
print ('')
print ("\033[33;42m################################################\033[0m")
print ("\033[33;42m#               CRONTAB INFO                   #\033[0m")
print ("\033[33;42m################################################\033[0m")
print (crontab)
print ('')
print ("\033[33;42m################################################\033[0m")