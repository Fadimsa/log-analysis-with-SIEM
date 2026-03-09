# log-analysis-with-SIEM

The log-analysis-with-SIEM lab from TryHackMe taught me how to use Splunk SIEM for L1 SOC workflows. I analyzed Windows, Linux, and web logs to detect brute-force attacks, web shells, privilege escalation, and persistence mechanisms through hands-on alert triage and correlation.
------------------------------------------------------------------------------------------------------
Skills Learned :- 

Advanced SIEM query writing using Splunk (index=, EventCode=, time binning, stats aggregation)

Log correlation across Windows Sysmon/WinEventLogs, Linux auth.log/syslog, web access logs

Attack timeline construction from initial access → privilege escalation → persistence

IOC extraction (IPs, malicious files, suspicious services, cron jobs)

Incident documentation with clear escalation recommendations for L2 analysts
------------------------------------------------------------------------------------------------------
Tools Used

Splunk SIEM - Centralised log analysis and search platform

Windows logs - Sysmon (EventCode 1/3), Security (4720/4722), System (7045/7036)

Linux logs - auth.log (SSH brute-force, sudo), syslog (cron persistence)

Web logs - Access logs for detecting POST floods, web shells, DDoS patterns
-----------------------------------------------------------------------------------------------------
Steps taken : 

I started with Sysmon logs to check out for things like 
1. Malicious Process Execution , i used this query : (index=winenv EventCode=1 *powershell* AND *EncodedCommand*
| table _time ComputerName ParentUser ParentImage ParentCommandLine Image CommandLine) 
and the it gave me this result : https://i.imgur.com/KocAcf1.png
2. Suspicious Network Connection , i used this query to check : (index=winenv EventCode=3 ComputerName=WINHOST05
| table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol)
  as shown in in this picture https://imgur.com/a/XUnPtE1 a suspicious connection was initiated by the suspicious process PPn423.exe from the Temp folder, targeting the unusual port 9999 on IP address 83.222.191.2. We also recommend checking this IP on TI platforms .

then i moved to work on winEventlogs
this logs contains alot of different logs including 
1. Windows Security Logs
2. Windows System Logs
   for  Windows Security Logs i used this query : (index=winenv EventCode=4720 OR EventCode=4722
| table _time EventCode ComputerName Subject_Account_Name Target_Account_Name New_Account_Account_Name Keywords) in order to see if The attacker likely decided to create a persistence mechanism in the form of a backup user account , and this is the result in the dashboard : https://imgur.com/a/u7Y3x3R


   for Windows system Logs i used this query : (index=winenv EventCode=7045 OR EventCode=7036 ComputerName=WINHOST05
|  table _time EventCode ComputerName Service_Name Service_Account Service_File_Name Message) to check up for any backup accounts to  look for potential persistence or privilege escalation and this is what ive got : https://imgur.com/a/apH7uWt

   
