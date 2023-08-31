---
layout: post
title: "[CVE-2021-37538] Improper neutralization of SQL parameter in SmartBlog module from SmartDataSoft for PrestaShop"
categories: module
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,smartblog"
severity: "critical (9.8)"
---

Multiple SQL injection vulnerabilities in SmartDataSoft SmartBlog for PrestaShop before 4.0.6 allow a remote unauthenticated attacker to execute arbitrary SQL commands via the day, month, or year parameter to the `controllers/front/archive.php` archive controller, or the id_category parameter to the `controllers/front/category.php` category controller.

## Summary

* **CVE ID**: [CVE-2021-37538](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-37538)
* **Published at**: 2021-08-24
* **Advisory source**: [sorcery.ie](https://blog.sorcery.ie/posts/smartblog_sqli/)
* **Vendor**: PrestaShop
* **Product**: SmartBlog
* **Impacted release**: < 4.0.6
* **Product author**: SmartDataSoft
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

In this smartblog module for PrestaShop, sorcery.ie discovered two SQLis.

In controllers/front/archive.php we can see that the day, month and year parameters are passed to the getArchiveResult() function without sanitisation.

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
* Copy/paste data from sensitive tables to the FRONT to exposed tokens and unlock admins' ajax scripts
* Rewrite SMTP settings to hijack emails

## Proof of concept

```bash
https://site.com/module/smartblog/archive?month=1&year=1&day=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT group_concat(name) FROM ps_module),NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -
```

## Patch

* Quick [to fix the issue with this patch](https://github.com/smartdatasoft/smartblog/commit/dcec2f77d98841ec478ca678ee501606224961b4).

## Other recommendations

* Upgrade the module to the most recent version
* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”) - be warned that this functionality WILL NOT protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 22-06-2021 | Issue discovered during a pentest |
| 13-07-2021 | Reported issue to SmartDataSoft |
| 15-07-2021 | SmartDataSoft patched the issue in version 4.0.6 |
| 26-07-2021 | Number CVE-2021-37538 assigned |
| 21-08-2021 | Blog post released |
| 24-08-2021 | pajoda made a Nuclei template for this CVE |

## Links

* [Source of this CVE](https://blog.sorcery.ie/posts/smartblog_sqli/)
* [National Vulnerability Database CVE-2021-37538](https://nvd.nist.gov/vuln/detail/CVE-2021-37538)
