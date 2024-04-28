---
layout: post
title: "[CVE-2024-33275] Improper neutralization of SQL parameter in Webbax - Super Newsletter module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,supernewsletter"
severity: "critical (9.8)"
---

In the module "Super Newsletter" (supernewsletter) up to version 1.4.21 (DANGER : all versions) from Webbax for PrestaShop, due to a predictable token, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2024-33275](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33275)
* **Published at**: 2024-04-29
* **Platform**: PrestaShop
* **Product**: supernewsletter
* **Impacted release**: <= 1.4.21 [WAITING FOR SCOPE]
* **Product author**: Webbax
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The script `product_search.php` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : This module is obsolete and must be deleted since author discontinue support.

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


## Patch from 1.4.21

```diff
--- 1.4.21/modules/supernewsletter/ajax/product_search.php
+++ XXXXXX/modules/supernewsletter/ajax/product_search.php
-       ps.`id_shop` = '.pSQL($id_shop).' AND
-       pl.`id_shop` = '.pSQL($id_shop).' AND
-       pl.`id_lang` = '.pSQL($id_lang).'
+       ps.`id_shop` = '.(int) $id_shop.' AND
+       pl.`id_shop` = '.(int) $id_shop.' AND
+       pl.`id_lang` = '.(int) $id_lang.'
```

## Other recommendations

* It’s recommended to delete the module since support is discontinue.
* You should consider restricting the access of /modules/supernewsletter/ajax/ to a whitelist
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-11-19 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-11-19 | Contact Author to confirm version scope by author |s
| 2024-04-23 | Received CVE ID |
| 2024-04-29 | Publish this security advisory |

## Links

* [Author page](https://www.webbax.ch/2017/08/30/9-modules-prestashop-gratuits-offert-par-webbax/)
* [Author page](https://shop.webbax.ch/prestashop-15-/71-module-supernewsletter-15.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-33275)