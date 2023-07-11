---
layout: post
title: "[CVE-2023-33278] Improper neutralization of multiple SQL parameters in the scexportcustomers module for PrestaShop"
categories: modules
author:
- Store Commander
- 202 ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,scexportcustomers"
severity: "critical (9.8)"
---

In the module "SC Export Customers" (scexportcustomers), an anonymous user can perform SQL injections. The module have been patched in version 3.6.2.

## Summary

* **CVE ID**: [CVE-2023-33278](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33278)
* **Published at**: 2023-05-25
* **Platform**: PrestaShop
* **Product**: scexportcustomers
* **Impacted release**: <= 3.6.1 (3.6.2 fixed the vulnerability)
* **Product author**: Store Commander
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

In scexportcustomers module up to 3.6.1 for PrestaShop, a sensitive SQL call can be executed with a trivial http call and exploited to forge a blind SQL injection.

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

* It's recommended to delete the module if not used or contact Store Commander
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix ps_ by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942’s rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-09-21 | Issue discovered after a security audit by [202-ecommerce](https://www.202-ecommerce.com) |
| 2022-09-21 | Contact Author |
| 2022-12-09 | Author provide patch |
| 2023-05-15 | Request a CVE ID |
| 2023-05-22 | Received CVE ID |

Store Commander thanks [202-ecommerce](https://www.202-ecommerce.com) for its courtesy and its help after the vulnerability disclosure.

## Links

* [Store Commander export customer module product page](https://www.storecommander.com/fr/modules-complementaires/480-export-clients-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-33278)
