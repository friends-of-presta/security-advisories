---
layout: post
title: "[CVE-2024-36684] Improper neutralization of SQL parameter in Promokit.eu - Custom links module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 ecommerce.com
meta: "CVE,PrestaShop,pk_customlinks"
severity: "critical (9.8)"
---

In the module "Custom links" (pk_customlinks) from Promokit.eu for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2024-36684](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-36684)
* **Published at**: 2024-06-18
* **Platform**: PrestaShop
* **Product**: pk_customlinks
* **Impacted release**: <= 2.3 (see WARNING below)
* **Product author**: Promokit.eu
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The script ajax.php have a sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING 2** : Versions declared as impacted are versions where we confirmed critical issue. Author don't know which exacts versions are impacted, he only said us that it was a long time ago. Author refuse to provide the last version to let us check that all is fixed. So you should consider that all versions can be impacted.

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
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admin's ajax scripts
* Rewrite SMTP settings to hijack emails


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **pk_customlinks**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2024-03-30 | Issue discovered during a code review by [TouchWeb](https://www.touchweb.fr) |
| 2024-03-30 | Contact Author to confirm version scope |
| 2024-03-30 | Author don't know which version is impacted but confirm us that it was a long time ago |
| 2024-03-30 | Author refuse to provide us the last version to check if it is fixed |
| 2024-06-06 | Received CVE ID |
| 2024-06-18 | Publish this security advisory |

## Links

* [Author product page](https://promokit.eu/)
* [Theme forest author page](https://themeforest.net/user/promokit)
* [Theme forest product page](https://themeforest.net/item/alysum-premium-responsive-prestashop-16-theme/2622574)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-36684)
