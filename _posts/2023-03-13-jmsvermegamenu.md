---
layout: post
title: "[CVE-2023-29630] Blind SQL injection vulnerability in Jms Vertical MegaMenu (jmsvermegamenu) PrestaShop module"
categories: modules
author:
- Creabilis.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
severity: "critical (9.8)"
---

The module Jms Vertical MegaMenu (jmsvermegamenu) from Joommasters contains a Blind SQL injection vulnerability.
This module is for the PrestaShop e-commerce platform and mainly provided with joo masters PrestaShop themes

## Summary

* **CVE ID**: [CVE-2023-29630](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29630)
* **Published at**: 2023-03-13
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: jmsvermegamenu
* **Impacted release**: at least 1.1.x and 2.0.x
* **Product author**: Joommasters
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

ajax_jmsvermegamenu.php hold sensitives SQL calls that can be executed with a trivial http call and exploited to forge a blind SQL injection.


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
--- a/ajax_jmsvermegamenu.php
+++ b/ajax_jmsvermegamenu.php
@@ -29,1 +29,1 @@ function getPosts
-        UPDATE `'._DB_PREFIX_.'jmsvermegamenu` SET `params` = \''.Tools::getValue('params').'\'
+        UPDATE `'._DB_PREFIX_.'jmsvermegamenu` SET `params` = \''.pSQL(Tools::getValue('params')).'\'
```

## Timeline

| Date | Action |
|--|--|
| 2022-09-01 | Issue discovered during a pentest |
| 2023-02-17 | Contact the author |
| 2023-03-13 | Publish this security advisory |

## Other recommendations

* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [Joom masters web site](https://www.joommasters.com/)
