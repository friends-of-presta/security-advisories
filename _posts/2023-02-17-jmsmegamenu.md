---
layout: post
title: "Blind SQL injection vulnerability in Jms MegaMenu (jmsmegamenu) PrestaShop module"
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

* **CVE ID**: To request
* **Published at**: 2023-02-17
* **Advisory source**: none
* **Vendor**: PrestaShop
* **Product**: jmsmegamenu
* **Impacted release**: at least 1.1.x and 2.0.x
* **Product author**: Joommasters
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

ajax_jmsmegamenu.php hold sensitives SQL calls that can be executed with a trivial http call and exploited to forge a blind SQL injection.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Possible malicious usage

This vulnerability permits altering the shop’s database.

## Patch of release 2.5.6

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
| 2023-02-17 | Publish this security advisory |

## Other recommandations

None

## Links

* [Joom masters web site](https://www.joommasters.com/)
