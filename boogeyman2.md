SOC Level 1 Capstone Challenge: Boogeyman 2

Objective: After having a severe attack from the Boogeyman, Quick Logistics LLC improved its security defenses. However, the Boogeyman returns with new and improved tactics, techniques and procedures.

In this room, you will be tasked to analyze the new tactics, techniques, and procedures (TTPs) of the threat group named Boogeyman.

Prerequisites

This room may require the combined knowledge gained from the  Path. We recommend going through the following rooms before attempting this challenge.





Investigation Platform

Before we proceed, deploy the attached machine by clicking the Start Machine button in the upper-right-hand corner of the task. It may take up to 3-5 minutes to initialise the services.

The machine will start in a split-screen view. If the VM is not visible, use the blue Show Split View button at the top-right of the page.

Artefacts

For the investigation, you will be provided with the following artefacts:

Copy of the phishing email.

Memory dump of the victim's workstation.

You may find these files in the /home/ubuntu/Desktop/Artefacts directory.





Tools

﻿The provided VM contains the following tools at your disposal:

Volatility - an  for extracting digital artefacts from volatile memory (RAM) samples.

ubuntu@tryhackme:~

ubuntu@tryhackme$ # Volatility usage:

ubuntu@tryhackme$ vol -f memorydump.raw <plugin>


# To list all available plugins

ubuntu@tryhackme$ vol -f memorydump.raw -h

Note: Volatility may take a few minutes to parse the memory dump and run the plugin. For plugin reference, check the Volatility 3 .

Olevba - a tool for analysing and extracting VBA macros from Microsoft Office documents. This tool is also a part of the .

ubuntu@tryhackme:~

ubuntu@tryhackme$ # Olevba usage:

ubuntu@tryhackme$ olevba document.doc


Task 2: Spear Phishing Human Resources

What email was used to send the phishing email?

What is the email of the victim employee?

What is the name of the attached malicious document?

What is the MD5 hash of the malicious attachment?

What URL is used to download the stage 2 payload based on the document's macro?

One of the provided tools was Olevba, which allows us to extract VBA macros from .doc files. Running the command gives us this url:

What is the name of the process that executed the newly downloaded stage 2 payload?


We can also see two executable file names, and the process was wscript.exe.

What is the full file path of the malicious stage 2 payload?


Above the table is the process path.

What is the PID of the process that executed the stage 2 payload?

Now we can move onto using Volatility. We can use pstree to see the processes and the parent IDs of processes. The PID is 4260


What is the parent PID of the process that executed the stage 2 payload?

The number on the right of PID is the parent process, which is 1124.

What URL is used to download the malicious binary executed by the stage 2 payload?

From earlier, we can see that boogeyman is part of a new url that they have used to carry out the attack. Looking through the WKSTN-2961 file via strings and using grep to search for “boogeyman” gives us a lot of info.

What is the PID of the malicious process used to establish the C2 connection?

With the info discovered in the previous question, we can also see that another process was used, which was update.exe. Looking back at the process tree, updater is present, but not update.exe. However this is still the correct PID

What is the full file path of the malicious process used to establish the C2 connection?

Going back to strings, I searched for updater.exe and found this path: C:\Windows\Tasks\updater.exe


What is the IP address and port of the C2 connection initiated by the malicious binary? (Format: IP address:port)

For this, I went back to volatility and used the netscan plugin, and the IP address and the port is present.What is the full file path of the malicious email attachment based on the memory dump?

I used the windows.filescan plugin to find this, and grep-ed the file that was attached to the email. For some reason it took a long time to load, but I found it:

The attacker implanted a scheduled task right after establishing the c2 callback. What is the full command used by the attacker to maintain persistent access?

This one was a bit tricky, but I did some research and a notable keyword I found was schtasks, so I used strings to search for it in the .raw file.



