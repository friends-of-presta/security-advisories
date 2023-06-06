---
layout: post
title: "[CVE-2023-29632] Blind SQL injection vulnerability in Jms Page Builder (jmspagebuilder) PrestaShop module"
categories: modules
author:
- Creabilis.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
severity: "critical (9.8)"
---

The module Jms Page Builder (jmspagebuilder) from Joommasters contains a Blind SQL injection vulnerability.
This module is for the PrestaShop e-commerce platform and mainly provided with joo masters PrestaShop themes

## Summary

* **CVE ID**: [CVE-2023-29632](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29632)
* **Published at**: 2023-03-13
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: jmspagebuilder
* **Impacted release**: at least 3.x
* **Product author**: Joommasters
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

ajax_jmspagebuilder.php hold sensitives SQL calls that can be executed with a trivial http call and exploited to forge a blind SQL injection.

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
--- a/ajax_jmspagebuilder.php
+++ b/ajax_jmspagebuilder.php
@@ -611,1 +611,1 @@ function getPosts
-        $where  = ' WHERE i.`id_product` IN ('.$productids.') AND (i.`cover` IS NULL OR i.`cover` = 0)';
+        $where  = ' WHERE i.`id_product` IN ('.implode(',', array_map('intval', explode(',', $productids))).') AND (i.`cover` IS NULL OR i.`cover` = 0)';
```

## Timeline

| Date | Action |
|--|--|
| 2022-09-01 | Issue discovered during a pentest |
| 2023-02-17 | Contact the author |
| 2023-03-13 | Publish this security advisory |

## Other recommandations

* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhat with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [Joom masters web site](https://www.joommasters.com/)
