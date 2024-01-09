---
layout: post
title: "[CVE-2023-6921] Improper neutralization of SQL parameter in PrestaShow Google Integrator module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,pshowconversion"
severity: "critical (9.8)"
---

Blind SQL Injection vulnerability in PrestaShow Google Integrator (pshowconversion) allows for data extraction and modification. This attack is possible via command insertion in one of the cookies.

## Summary

* **CVE ID**: [CVE-2023-6921](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6921)
* **Published at**: 2024-01-09
* **Advisory source**: [Piotr Zdunek](https://cert.pl/posts/2024/01/CVE-2023-6921/)
* **Platform**: PrestaShop
* **Product**: pshowconversion
* **Impacted release**: < 2.1.4
* **Product author**: Presta Show
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)


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
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **pshowconversion**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2024-01-09 | Publish this security advisory |


## Links

* [Product author page](https://prestashow.pl/pl/moduly-prestashop/28-prestashop-google-integrator-ga4-gtm-ads-remarketing.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-6921)

