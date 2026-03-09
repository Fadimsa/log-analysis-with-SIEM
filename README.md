# log-analysis-with-SIEM

The log-analysis-with-SIEM lab from TryHackMe taught me how to use Splunk SIEM for L1 SOC workflows. I analyzed Windows, Linux, and web logs to detect brute-force attacks, web shells, privilege escalation, and persistence mechanisms through hands-on alert triage and correlation.

Skills Learned
Advanced SIEM query writing using Splunk (index=, EventCode=, time binning, stats aggregation)

Log correlation across Windows Sysmon/WinEventLogs, Linux auth.log/syslog, web access logs

Attack timeline construction from initial access → privilege escalation → persistence

IOC extraction (IPs, malicious files, suspicious services, cron jobs)

Incident documentation with clear escalation recommendations for L2 analysts

Tools Used
Splunk SIEM - Centralised log analysis and search platform

Windows logs - Sysmon (EventCode 1/3), Security (4720/4722), System (7045/7036)

Linux logs - auth.log (SSH brute-force, sudo), syslog (cron persistence)

Web logs - Access logs for detecting POST floods, web shells, DDoS patterns

Steps taken : 
I started with Sysmon logs to check out for things like 
1 : Malicious Process Execution , i used this query : index=winenv EventCode=1 *powershell* AND *EncodedCommand*
| table _time ComputerName ParentUser ParentImage ParentCommandLine Image CommandLine 
and the it gave me this result : https://i.imgur.com/KocAcf1.png

