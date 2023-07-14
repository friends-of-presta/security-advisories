---
layout: post
title: "[CVE-2021-36748] Improper neutralization of SQL parameter in SimpleBlog module from Prestahome for PrestaShop"
categories: module
author:
- Sorcery Ltd
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ph_simpleblog"
severity: "critical (9.8)"
---

A SQL Injection issue in the list controller of the Prestahome Blog (aka ph_simpleblog) module before 1.7.8 for Prestashop allows a remote attacker to extract data from the database via the sb_category parameter.

## Summary

* **CVE ID**: [CVE-2021-36748](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36748)
* **Published at**: 2021-08-20
* **Advisory source**: [sorcery.ie](https://blog.sorcery.ie/posts/simpleblog_sqli/)
* **Platform**: PrestaShop
* **Product**: ph_simpleblog
* **Impacted release**: < 1.7.8
* **Product author**: Prestahome
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

This blog post details an SQLi sorcery.ie found in Blog for Prestashop (ph_simpleblog) by Prestahome.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to the FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch

Prestashop provide a built in function for sanitising strings to be used in SQL queries called pSQL. This is the quick fix in situations like this but one must be sure to surround the parameter with quotes or the query will still be vulnerable to SQLi

The most correct way to patch this would be to use PDO as desribed in Prestashop’s [Best Practices for the DB Class](https://docs.prestashop-project.org/1-6-documentation/). PDO eliminates the risks of faulty parameter sanitisation and makes it hard to do things the wrong way.

## Other recommendations

* Upgrade the module to the most recent version
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 18-06-2021 | Issue discovered during a pentest |
| 13-07-2021 | Reported issue to Prestahome |
| 14-07-2021 | Prestahome patched the issue in version 1.7.8 |
| 15-07-2021 | Number CVE-2021-36748 assigned |
| 18-08-2021 | Blog post released |
| 20-08-2021 | pajoda released a Nuclei template for this CVE |

## Links

* [Source of this CVE](https://blog.sorcery.ie/posts/ph_simpleblog_sqli/)
* [National Vulnerability Database CVE-2021-36748](https://nvd.nist.gov/vuln/detail/CVE-2021-36748)
