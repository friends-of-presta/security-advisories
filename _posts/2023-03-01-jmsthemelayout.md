---
layout: post
title: "Blind SQL injection vulnerability in Jms Theme Layout (jmsthemelayout) PrestaShop module"
categories: modules
author:
- Creabilis.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
severity: "critical (9.8)"
---

The module Jms Theme Layout (jmsthemelayout) from Joommasters contains a Blind SQL injection vulnerability.
This module is for the PrestaShop e-commerce platform and mainly provided with joo masters PrestaShop themes

## Summary

* **CVE ID**: To request
* **Published at**: 2023-03-01
* **Advisory source**: none
* **Vendor**: PrestaShop
* **Product**: jmsthemelayout
* **Impacted release**: at least 2.5.5
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

**Vector string**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Possible malicious usage

This vulnerability permits altering the shop’s database.

## Patch

```diff
--- a/ajax_jmsthemelayout.php.php
+++ b/ajax_jmsthemelayout.php.php
@@ -102,2 +102,2 @@ function getPosts
-        $query = 'UPDATE `'._DB_PREFIX_.'jmsadv_position` SET `col_lg` = '.$pos_obj[1].', `col_md` = '.$pos_obj[2].', `col_sm` = '.$pos_obj[3].', `col_xs` = '.$pos_obj[4].
-		'	WHERE `id_position` = '.$pos_obj[0];
+        $query = 'UPDATE `'._DB_PREFIX_.'jmsadv_position` SET `col_lg` = '. (int)$pos_obj[1].', `col_md` = '. (int)$pos_obj[2].', `col_sm` = '. (int)$pos_obj[3].', `col_xs` = '. (int)$pos_obj[4].
+		'	WHERE `id_position` = '. (int)$pos_obj[0];
```

## Timeline

| Date | Action |
|--|--|
| 2022-09-01 | Issue discovered during a pentest |
| 2023-02-17 | Contact the autor |
| 2023-02-17 | Publish this security advisory |

## Other recommandations

None

## Links

* [Joom masters web site](https://www.joommasters.com/)
