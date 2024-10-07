---
layout: page
title: Cybersecurity Glossary
permalink: /glossary/
---

Cybersecurity is the practice of protecting computers, networks, and data from unauthorized access, attacks, or damage. It involves a range of technologies, processes, and best practices designed to safeguard digital systems from cyber threats, such as hacking, malware, and data breaches. This glossary provides clear definitions of essential cybersecurity terms, helping users understand the key concepts and tools used to defend against these growing digital risks.

# Various terms used in Advisories

| Term | Meaning | Definition |
|------|---------|------------|
| [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures) | Common Vulnerabilities and Exposures. | System that provides a reference method for publicly known information-security vulnerabilities and exposures. |
| CVE ID | CVE Identifier | An alphanumeric string that identifies a Publicly Disclosed vulnerability. The format of the CVE ID is defined in the CVE Record Format. |
| [CWE](https://en.wikipedia.org/wiki/Common_Weakness_Enumeration) | Common Weakness Enumeration | Category system for hardware and software weaknesses and vulnerabilities. Check the [top 25 CWE of 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html). |
| CNA | CVE Numbering Authority | An authorized entity with specific scope and responsibility to regularly assign CVE IDs and publish corresponding CVE Records. |
| Fix || A change to software to remediate, mitigate, or otherwise address a vulnerability. “Fix” is used broadly and includes terms such as patch, fix, hotfix, update, and upgrade.|
| POC | proof of concept | A proof of concept is a prototype that demonstrates the viability of a vulnerabilty |
| [CVSS](https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System) | Common Vulnerability Scoring System | A free and open industry standard for assessing the severity of computer system security vulnerabilities. |
| SU | Super user | vulnerabilities accessible only under authentication (weak via unpredictable immutable token or strong via login / password or token with a limited lifespan) |
| P1 / P2 / P3 | Phase 1 / 2 / 3 | [Different phases of a cyber-attack](#phases-of-a-cyber-attack) |

## Phases of a cyber-attack

In the context of a cybersecurity attack, there are generally three phases often referred to as **P1 (Pre-attack)**, **P2 (Attack/Exploit)**, and **P3 (Post-attack)**. Understanding these phases is critical for developers to better protect systems from attacks and respond effectively when they occur.

### Phase 1: Pre-Attack (P1) - Reconnaissance and Preparation

In this phase, the attacker gathers information about the target and prepares for the attack. The goal is to identify vulnerabilities or weaknesses in the system or network that can be exploited later.

It consists of an innocent call on a static file - usually an image, a style sheet or a javascript file that allows a hacker to confirm the existence of a module / plugin on the E-Commerce site.

### Phase 2: Attack/Exploit (P2) - Initial Compromise

During this phase, the attacker attempts to exploit the identified vulnerabilitie.

It consists of a call with harmless payload - the hacker knows that you have the module / plugin he is looking for, he wants to know if it suffers from the critical security vulnerability he is looking for.

### Phase 3: Post-Attack (P3) - Persistence, Covering Tracks, and Exfiltration

The hacker goes on the attack, the hacker knows that you have the module / plugin he is looking for in the version that has the critical vulnerability he wants to exploit and therefore takes action.

After gaining access, the attacker typically has long-term objectives such as maintaining access, stealing sensitive information, or causing damage. They also attempt to avoid detection and cover their tracks.

# Type of vulnerability

All categories [are available on NIST site](https://nvd.nist.gov/vuln/categories).

| Term | CWE | Meaning |
|------|---------|
| [SQLi](https://en.wikipedia.org/wiki/SQL_injection) | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | SQL injection |
| [RCE](https://en.wikipedia.org/wiki/RCE_-_Remote_Code_Execution) | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Remote Code Execution |
| [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Cross-site Scripting |
| [SSRF](https://en.wikipedia.org/wiki/Server-side_request_forgery) | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | Server-side request forgery |
| [XXE](https://en.wikipedia.org/wiki/XML_external_entity_attack) | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | XML External Entity attack | 
| [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Cross-Site Request Forgery | 
