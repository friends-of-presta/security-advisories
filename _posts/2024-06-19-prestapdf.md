---
layout: post
title: "[CVE-2024-34989] Improper neutralization of SQL parameter in RSI PDF/HTML catalog evolution (prestapdf) module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202-ecommerce.com
meta: "CVE,PrestaShop,prestapdf"
severity: "critical (9.8)"
---

In the module RSI PDF/HTML catalog evolution (prestapdf) before version 7.0.x (TO BE CONFIRMED) from RSI for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2024-34989](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34989)
* **Published at**: 2024-12-xx
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: prestapdf
* **Impacted release**: ALL (see Note below)
* **Product author**: RSI
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `PrestaPDFProductListModuleFrontController::queryDb()` has multiple sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

Parameters `id_product`, `langs`, `skipcat` are sensitives parameter.

**WARNING** : Author refuse to patch the vulnerability so you should consider to uninstall it. There is strong design issue which cannot be fixed by a hotfix. Version tagged as impacted is the only version we had time to produce a POC for it, author has updated things in newer versions but its token is still predictible. So you should consider that all versions are impacted.


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
* Complete takeover


## Other recommendations

* It’s recommended to **delete this module**.
* Activate OWASP 933's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-11-24 | Issue discovered during a code review by [202-ecommerce.com](https://www.202-ecommerce.com/) |
| 2023-11-24 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-11-27 | PrestaShop Addons security Team confirm versions scope by author |
| 2023-12 to 2024-05 | Relaunch several time for patch |
| 2024-05-29 | PrestaShop Addons put offline the module |
| 2024-06-06 | Received CVE ID |
| 2024-06-18 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/import-export-de-donnees/2063-rsi-presta-pdf-html-export-catalog.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-34989)

