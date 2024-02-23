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
* **Impacted release**: <= 7.8.a (ALL VERSIONS)
* **Product author**: Sitolog
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

In sitologapplicationconnect module from Sitolog for PrestaShop up to version 7.8.a (all versions), a sensitive SQL call can be executed with a trivial http call and exploited to forge a blind SQL injection.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards.

**This obsolete module has been replaced since 2018 by the new module renamed "Sitolog Connector".**

Note : the most recent version (currently V9.0) of "Sitolog Connector" is available to download for free for all Sitolog customers on www.sitolog.com. This up to date connector supports all our applications versions.

As a reminder, the 3 older applications PrestaPricing, PrestaCategories and Merlin Backoffice standard are also obsolete (no more update either support) and must be replaced by Merlin Backoffice Flex using more recent technologies (http2 instead of http1, support of PHP8, MySQL above 7.5 ...).

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

* It's recommended to delete this module and download the new module freely available on www.sitolog.com
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
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
