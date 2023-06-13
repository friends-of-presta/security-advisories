---
layout: post
title: "[CVE-2023-30150] Improper neutralization of SQL parameters in the Leo Custom Ajax (leocustomajax) module from LeoTheme for PrestaShop"
categories: module
author:
- Profileo.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,leocustomajax"
severity: "critical (9.8)"
---

Multiple SQL injection vulnerabilities in the Leo Custom Ajax (leocustomajax) module from LeoTheme for PrestaShop, in version 1.0, allow remote attackers to execute arbitrary SQL commands via the `cat_list`, `pro_info`, `pro_add`, `pro_cdown` or `pro_color` parameter in `leoajax.php`.

## Summary

* **CVE ID**: [CVE-2023-30150](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30150)
* **Published at**: none
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: leocustomajax
* **Impacted release**: = 1.0 (May also be identified as 1.0.0)
* **Product author**: LeoTheme
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

In the Leo Custom Ajax (leocustomajax) module for PrestaShop, in version 1.0 and 1.0.0 (no other versions have been published since), an HTTP request can be manipulated using multiple GET parameters (`cat_list`, `pro_info`, `pro_add`, `pro_cdown` and `pro_color`), in the `/modules/leocustomajax/leoajax.php` endpoint, enabling a remote attacker to perform an SQL injection.

**WARNING** : This vulnerability can be exploited even if the module is disabled or uninstalled, and is actively used to deploy webskimmer to massively steal credit cards.

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
* Remove data on the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijacked emails

## Proof of concept

```bash
https://example.test/modules/leocustomajax/leoajax.php?cat_list=10%29;select+0x73656C65637420736C656570283432293B+into+@a;prepare+b+from+@a;execute+b;--
```

## Patch 

**Disabling or uninstalling the module is not enough. The module needs to be fully removed from the file system or patched.**

```diff
--- a/modules/leocustomajax/leoajax.php
+++ b/modules/leocustomajax/leoajax.php
@@ -25,6 +25,7 @@ $leoProductInfo = new Leocustomajax();
 if ($listCat) {
     $listCat = explode(',', $listCat);
     $listCat = array_unique($listCat);
+    $listCat = array_map('intval', $listCat);
     $listCat = implode(',', $listCat);
 
     $sql = 'SELECT COUNT(cp.`id_product`) AS total, cp.`id_category`
@@ -44,6 +45,7 @@ if ($listCat) {
 if ($leoProCdown) {
     $leoProCdown = explode(',', $leoProCdown);
     $leoProCdown = array_unique($leoProCdown);
+    $leoProCdown = array_map('intval', $leoProCdown);
     $leoProCdown = implode(',', $leoProCdown);
     $result['pro_cdown'] = $leoProductInfo->hookProductCdown($leoProCdown);
 }
@@ -51,6 +53,7 @@ if ($leoProCdown) {
 if ($leoProColor) {
     $leoProColor = explode(',', $leoProColor);
     $leoProColor = array_unique($leoProColor);
+    $leoProColor = array_map('intval', $leoProColor);
     $leoProColor = implode(',', $leoProColor);
     $result['pro_color'] = $leoProductInfo->hookProductColor($leoProColor);
 }
@@ -59,6 +62,7 @@ if ($leoProColor) {
 if ($leoProInfo) {
     $leoProInfo = explode(',', $leoProInfo);
     $leoProInfo = array_unique($leoProInfo);
+    $leoProInfo = array_map('intval', $leoProInfo);
     $leoProInfo = implode(',', $leoProInfo);
 
     # $leocustomajax = new Leocustomajax();
@@ -67,6 +71,7 @@ if ($leoProInfo) {
 if ($leoProAdd) {
     $leoProAdd = explode(',', $leoProAdd);
     $leoProAdd = array_unique($leoProAdd);
+    $leoProAdd = array_map('intval', $leoProAdd);
     $leoProAdd = implode(',', $leoProAdd);
 
     $result['pro_add'] = $leoProductInfo->hookProductOneImg($leoProAdd);
```

## Other recommendations

* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skilled because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 2022-09-18 | Discovery of the vulnerability by Profileo |
| 2022-09-19 | Security issue reported to the author |
| 2022-09-20 | Issue confirmed by the author |
| 2023-03-25 | Request for additional details concerning impacted versions |
| 2023-03-28 | Author replied confirming versions impacted |
| 2023-06-06 | Publication of the security advisory |

## Links

* [Module's author website LeoTheme](https://www.leotheme.com/)
* [National Vulnerability Database CVE-2023-30150](https://nvd.nist.gov/vuln/detail/CVE-2023-30150)
