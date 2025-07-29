SOC Level 1 Capstone Challenge: Boogeyman 3

Due to the previous attacks of Boogeyman, Quick Logistics LLC hired a managed security service provider to handle its Security Operations Center. Little did they know, the Boogeyman was still lurking and waiting for the right moment to return.

In this room, you will be tasked to analyse the new tactics, techniques, and procedures (TTPs) of the threat group named Boogeyman.

Prerequisites

This room may require the combined knowledge gained from the  Path. We recommend going through the following rooms before attempting this challenge.






Investigation Platform

Before we proceed, deploy the attached machine by clicking the Start Machine button in the upper-right-hand corner of the task. The provided virtual machine runs an Elastic Stack (ELK), which contains the logs that will be used throughout the room.











Task 2: The Chaos Inside

Lurking in the Dark

Without tripping any security defenses of Quick Logistics LLC, the Boogeyman was able to compromise one of the employees and stayed in the dark, waiting for the right moment to continue the attack. Using this initial email access, the threat actors attempted to expand the impact by targeting the CEO, Evan Hutchinson.


The email appeared questionable, but Evan still opened the attachment despite the skepticism. After opening the attached document and seeing that nothing happened, Evan reported the phishing email to the security team.

Initial Investigation

Upon receiving the phishing email report, the security team investigated the workstation of the CEO. During this activity, the team discovered the email attachment in the downloads folder of the victim.


In addition, the security team also observed a file inside the ISO payload, as shown in the image below.


Lastly, it was presumed by the security team that the incident occurred between August 29 and August 30, 2023.

Given the initial findings, you are tasked to analyze and assess the impact of the compromise.


What is the PID of the process that executed the initial stage 1 payload?Top of FormTop of Form

To start off, based on the initial information, the initial payload was ProjectFinancialSummary_Q3.pdf. So I searched for that in Elastic. With that, we can see the PID.

The stage 1 payload attempted to implant a file to another location. What is the full command-line value of this execution?Top of Form

I wasn’t sure exactly what to be looking for, but I still kept the same search query and applied a command_line filter to easily see what was executed.: "C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat

The implanted file was eventually used and executed by the stage 1 payload. What is the full command-line value of this execution?

The next command is also present in the previous screenshot: "C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer

The stage 1 payload established a persistence mechanism. What is the name of the scheduled task created by the malicious script?

Since a persistence mechanism was established, I look through the results to see if any new scheduled tasks were created. Scanning through the lines, the name of the task is Review.


The execution of the implanted file inside the machine has initiated a potential C2 connection. What is the IP and port used by this connection? (format: IP:port)

Doing some research, since this command was executed by powershell and the logs came from Sysmon, I can apply a filter to narrow down the results. Event code 3 means network connection. Using this, when clicking on the filters, you can see the top results.


The attacker has discovered that the current access is a local administrator. What is the name of the process used by the attacker to execute a UAC bypass?

A file that came up in the initial query was review.dat, so searching for that in elastic yielded some results. Doing a search on the executables used and “uac bypass”, it looks like fodhelper was used as a bypass.


Having a high privilege machine access, the attacker attempted to dump the credentials inside the machine. What is the GitHub link used by the attacker to download a tool for credential dumping?

This was simple. I searched for github and it tells us that mimikatz was used.


After successfully dumping the credentials inside the machine, the attacker used the credentials to gain access to another machine. What is the username and hash of the new credential pair? (format: username:hash)

Since we found that it’s mimikatz, we can search for it in elastic stack,


I copied the encoded message on the right but there was nothing useful, until I noticed that there was a user name and ntlm hash:

itadmin:F84769D250EB95EB2D7D8B4A1C5613F2

Using the new credentials, the attacker attempted to enumerate accessible file shares. What is the name of the file accessed by the attacker from a remote share?

While looking through the workstation, I put powershell in the search query to see if there were any interesting files downloaded. I there was a ps1 and I filtered it into the search query.


After getting the contents of the remote file, the attacker used the new credentials to move laterally. What is the new set of credentials discovered by the attacker? (format: username:password)

Using the same filter, I looked through the command line and got rid of any empty commands.

What is the hostname of the attacker's target machine for its lateral movement attempt?

WKSTN-1327, which was found earlier with the mimikatz execution.

Using the malicious command executed by the attacker from the first machine to move laterally, what is the parent process name of the malicious command executed on the second compromised machine?

Knowing the host machine, we can now change our filter to use that one, and filter event codes by 1, which indicates process creations.

Wsmprovhost.exe


The attacker then dumped the hashes in this second machine. What is the username and hash of the newly dumped credentials? (format: username:hash)

Since I conducted my investigation a bit of order, I saw earlier that there were administrator credentials, so I went back to look for them.


After gaining access to the domain controller, the attacker attempted to dump the hashes via a DCSync attack. Aside from the administrator account, what account did the attacker dump?

I queried DCSync in the search bar:


After dumping the hashes, the attacker attempted to download another remote file to execute ransomware. What is the link used by the attacker to download the ransomware binary?


Okay, so now we know the exact hostname, the user account the attacker is using, and the parent process used. With this information we can filter our events to look for those specifically, and we can find the link that was used by the attacker.

