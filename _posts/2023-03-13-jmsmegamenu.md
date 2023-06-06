---
layout: post
title: "[CVE-2023-29630] Blind SQL injection vulnerability in Jms MegaMenu (jmsmegamenu) PrestaShop module"
categories: modules
author:
- Creabilis.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
severity: "critical (9.8)"
---

The module Jms MegaMenu (jmsmegamenu) from Joommasters contains a Blind SQL injection vulnerability.
This module is for the PrestaShop e-commerce platform and mainly provided with joo masters PrestaShop themes

## Summary

* **CVE ID**: [CVE-2023-29630](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29630)
* **Published at**: 2023-03-13
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: jmsmegamenu
* **Impacted release**: at least 1.1.x and 2.0.x
* **Product author**: Joommasters
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

ajax_jmsmegamenu.php hold sensitives SQL calls that can be executed with a trivial http call and exploited to forge a blind SQL injection.

**WARNING** : This exploit is actively used to deploy webskimmer to massively steal credit cards. 

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
* Display sensitives tables to front-office to unlock potential admin's ajax scripts of modules protected by token on the ecosystem

## Patch

```diff
--- a/ajax_jmsmegamenu.php
+++ b/ajax_jmsmegamenu.php
@@ -29,1 +29,1 @@ function getPosts
-        UPDATE `'._DB_PREFIX_.'jmsmegamenu` SET `params` = \''.Tools::getValue('params').'\'
+        UPDATE `'._DB_PREFIX_.'jmsmegamenu` SET `params` = \''.pSQL(Tools::getValue('params')).'\'
```

## Timeline

| Date | Action |
|--|--|
| 2022-09-01 | Issue discovered during a pentest |
| 2023-02-17 | Contact the author |
| 2023-03-13 | Publish this security advisory |

## Other recommandations

* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [Joom masters web site](https://www.joommasters.com/)
