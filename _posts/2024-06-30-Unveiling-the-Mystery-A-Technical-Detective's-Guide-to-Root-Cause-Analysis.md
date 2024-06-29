---
title: Unveiling the Mystery A Technical Detective's Guide to Root Cause Analysis
tags: RCA Investigation Digital-Forensics Logs-Anslysis
---


## Introduction

The digital world thrives on seamless operation. But when glitches creep in or cyberattacks strike, it's like hitting a roadblock on a high-speed journey. That's where I come in, your technical detective! For the past six months, I've been on a mission to solve these mysteries, conducting Root Cause Analysis (RCA) for a variety of technical glitches or cyber attacks.

In this blog series, I'll be sharing the captivating world of RCA, peeling back the layers to reveal the root cause of technical glitches and cyberattacks. Through captivating case studies (with client and data confidentiality strictly maintained, of course!), we'll delve into the thought process, the techniques employed, and the thrill of uncovering the culprit behind the disruption.

So, buckle up, tech enthusiasts and cybersecurity warriors! We're about to embark on a journey of troubleshooting and problem-solving, one RCA project at a time.

#### Case Study - 1: Unveiling the Culprit Behind a Ransomware Attack on a Stock Broking Firm

This case study dives into the investigation of a ransomware attack that targeted a stock broking firm (hereafter referred to as "the Company") offering services across various Indian stock exchanges. The objective is to dissect the attack methodology, pinpoint the root cause, and highlight the crucial learnings for fortifying cybersecurity measures.

**The Incident: A Night of Disruption**

On October 23rd, between 11 PM and midnight, the Company's infrastructure encountered a series of anomalies. The saga began with a workstation in a branch exhibiting suspicious activity. This workstation attempted to log in to another machine four times consecutively, deviating from the standard practice of a single login for data transmission.

Following these login attempts, the attacker unleashed a network scan across the entire subnet using a program called "advance_network_scanner.exe." This reconnaissance mission was likely aimed at identifying critical systems within the network.

Equipped with a network map, the attacker then initiated a Remote Desktop Protocol (RDP) attack on two crucial servers: one handling order management and another responsible for market data distribution. By executing PowerShell commands, the attacker gained administrator access to both servers, granting complete control.

As dawn approached on October 24th, between midnight and 1 AM, the compromised servers initiated a data encryption process, a hallmark of a ransomware attack. The IT team discovered files with suspicious extensions, along with a ransom note, confirming their suspicions.

**Cracking the Case: A Root Cause Analysis**

Our investigation to unearth the root cause of this attack revealed a confluence of vulnerabilities:

1. **Misconfigured Firewall Rule:** A firewall rule mistakenly allowed RDP connections from the internet to a workstation. This open door provided the attacker with an entry point into the network.
    
2. **Inadequate Endpoint Detection & Response (EDR) Rules:** The existing EDR rules deployed on the system were insufficient to detect and prevent the attacker's malicious activities.
    
3. **End-of-Life OS:** The workstation under attack was running on an operating system no longer supported by Microsoft and lacking essential security updates. This outdated system presented an easier target for exploits.
    

**Remediation and Recovery: Back on Track**

The Company's IT team responded swiftly to contain the attack. The infected servers were isolated to prevent further lateral movement within the network. Fortunately, data backups existed, and these backups were used to restore critical systems, enabling them to resume business operations well before the next trading day.

It's important to note that the ransomware attack also encrypted the backup data stored on the backup server, rendering it temporarily inaccessible.

**Lessons Learned: Building a Security Fortress**

This incident underscores the importance of a robust cybersecurity posture. Here are some key takeaways:

- **Firewall Configurations:** Regularly review and update firewall rules to ensure only authorized traffic enters the network.
- **EDR Efficacy:** Continuously evaluate and refine Endpoint Detection & Response (EDR) rules to stay ahead of evolving threats.
- **Patch Management:** Prioritize timely patching of operating systems and applications to address known vulnerabilities.
- **Staff Awareness:** Educate staff on cybersecurity best practices to identify and report suspicious activities.

The Company's commitment to implementing security standards demonstrates their dedication to information security. Their ongoing efforts to deploy advanced technical solutions, enforce baseline secure configurations, and conduct regular staff training will further bolster their cybersecurity defenses.

This case study serves as a cautionary tale, highlighting the potential consequences of security weaknesses. By adopting a multi-layered approach that combines technological safeguards with staff awareness, organizations can significantly reduce their attack surface and fortify their digital citadel.

---

**Activate-Windows(Wln5t0n)**

