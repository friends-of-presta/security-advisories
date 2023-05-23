---
layout: post
title: "[CVE-2023-33279] Improper neutralization of multiple SQL parameters in the scfixmyprestashop module for PrestaShop"
categories: modules
author:
- Store Commander
- TouchWeb
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,scfixmyprestashop"
severity: "critical (9.8)"
---

In the module "SC Export Customers" (scfixmyprestashop), an anonymous user can perform an SQL injection. The module is obsolete and must be deleted.

## Summary

* **CVE ID**: [CVE-2023-33279](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33279)
* **Published at**: 2023-
* **Platform**: PrestaShop
* **Product**: scfixmyprestashop
* **Impacted release**: All versions
* **Product author**: Store Commander
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

In scfixmyprestashop module for PrestaShop (all versions, must be deleted as soon as possible), a sensitive SQL calls can be executed with a trivial http call and exploited to forge a blind SQL injection.


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

* Technical and personal data leaks
* Obtain admin access
* Remove all data of the linked PrestaShop
* Display sensitives tables to front-office to unlock potential admin’s ajax scripts of modules protected by token on the ecosystem

## Timeline

| Date  | Action |
|--|--|
| 2022-09-21 | Issue discovered after a security audit by [TouchWeb](https://www.touchweb.fr) |
| 2022-09-21 | Contact Author |
| 2023-05-15 | Request a CVE ID |
| 2023-05-22 | Received CVE ID |

## Other recommandations

* It's recommended to delete the module
* Upgrade PrestaShop beyond 1.7.8.8 (and 8.0.1) to disable multiquery executions (separated by “;”).
* Change the default database prefix ps_ by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942’s rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

Store Commander thanks [TouchWeb](https://www.touchweb.fr) for its courtesy and its help after the vulnerability disclosure.

## Links

* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/name=CVE-2023-33279)
