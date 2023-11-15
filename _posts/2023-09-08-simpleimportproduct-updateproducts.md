---
layout: post
title: "[CVE-2023-39677] PHPInfo Exposure in MyPrestaModules SimpleImportProduct and UpdateProducts Modules"
categories: modules
author:
- Sorcery Ltd
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,simpleimportproduct,updateproducts"
severity: "medium (5.3)"
---

MyPrestaModules SimpleImportProduct Prestashop Module v6.2.9 and UpdateProducts Prestashop Module v3.6.9 were discovered to contain a PHPInfo information disclosure vulnerability via send.php.

## Summary

* **CVE ID**: [CVE-2023-39677](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39677)
* **Published at**: 2023-09-07
* **Platform**: PrestaShop
* **Product**: SimpleImportProduct / UpdateProducts
* **Impacted release**: < 6.4.0 / < v3.8.1
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
* **Severity**: {{ severity }}

## Description

Two modules that we tested by MyPrestaModules have a vulnerability where PHPInfo is exposed to an unauthenticated attacker. The modules SimpleImportProduct and UpdateProducts contain a file called send.php that has the following code snippet:

```php
if ( Tools::getValue('phpinfo') ){  
  phpinfo();  
  die;  
}
```

This exposes PHPInfo information **which could be a little** [EDIT FOP] useful to an attacker and it requires no authentication to exploit. This was reported to MyPrestaModules and a patch was released.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: low
* **Integrity**: none
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

## Patch

### simpleimportproduct

```diff
--- a/modules/simpleimportproduct/send.php
+++ b/modules/simpleimportproduct/send.php
@@ -9,5 +8,0 @@ include(dirname(__FILE__).'/../../config/config.inc.php');
-if ( Tools::getValue('phpinfo') ){
-  phpinfo();
-  die;
-}
```

### updateproducts

```diff
--- a/modules/updateproducts/send.php
+++ b/modules/updateproducts/send.php
@@ -9,5 +8,0 @@ include(dirname(__FILE__).'/../../config/config.inc.php');
-if ( Tools::getValue('phpinfo') ){
-  phpinfo();
-  die;
-}
```

## Other recommendations

* Upgrade the simpleimportproduct module to 6.4.0+
* Upgrade the UpdateProducts module to 3.8.1+

## Timeline

| Date | Action |
|--|--|
|10/07/2023	| Issue discovered during a pentest |
|12/07/2023	| Reported issue to MyPrestaModules |
|29/07/2023	| Requested CVE from MITRE |
|??/08/2023	| Patch released |
|28/08/2023	| Number CVE-2023-39677 assigned |
|07/09/2023	| Blog post and nuclei template released |

## Links

* [References](https://blog.sorcery.ie/posts/myprestamodules_phpinfo/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-39677)
* [Editor](https://myprestamodules.com/)
