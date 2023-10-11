---
layout: post
title: "[CVE-2023-37824] Improper neutralization of SQL parameters in the Sitolog Application Connect module from Sitolog for PrestaShop"
categories: modules
author:
- Sitolog
- TouchWeb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,sitologapplicationconnect"
severity: "critical (9.8)"
---

In the module "Sitolog Application Connect" (sitologapplicationconnect) from Sitolog for PrestaShop, an anonymous user can perform a SQL injection. **The module is obsolete and must be deleted.**

## Summary

* **CVE ID**: [CVE-2023-37824](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-37824)
* **Published at**: 2023-10-11
* **Platform**: PrestaShop
* **Product**: sitologapplicationconnect
* **Impacted release**: ALL VERSIONS **DANGER**
* **Product author**: Sitolog
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

In sitologapplicationconnect module from Sitolog for PrestaShop in all versions, a sensitive SQL call can be executed with a trivial http call and exploited to forge a blind SQL injection.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards.

**The module is obsolete since years and must be deleted.**

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

## Other recommendations

* It's recommended to delete the module
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix ps_ by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942’s rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date  | Action |
|--|--|
| 2022-12-29 | Issue discovered after a security audit by [TouchWeb](https://www.touchweb.fr) |
| 2022-12-29 | Contact Author to confirm version scope |
| 2022-12-29 | Author confirm version scope |
| 2023-07-08 | Request a CVE ID |
| 2023-10-09 | Received CVE ID |
| 2023-10-11 | Publish this security advisory |

Sitolog thanks [TouchWeb](https://www.touchweb.fr) for its courtesy and its help after the vulnerability disclosure.

## Links

* [Author product page](https://www.sitolog.com/fr/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-37824)
