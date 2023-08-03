---
layout: post
title: "[CVE-2023-26859] Multiple improper neutralizations of an SQL parameters in Sendinblue module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,sendinblue"
severity: "high (8.1)"
---

In the module "Sendinblue - All-in-one marketing tool" (sendinblue) up to versions 4.0.14 from Sendinblue for PrestaShop, an anonymous user can perform SQL injection in affected versions if double optin is enabled. 4.0.15 fixed vulnerabilities.

## Summary

* **CVE ID**: [CVE-2023-26859](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-26859)
* **Published at**: 2023-07-25
* **Advisory source**: Friends-of-Presta.org
* **Platform**: PrestaShop
* **Product**: sendinblue
* **Impacted release**: <= 4.0.14 (4.0.15 fixed the vulnerability)
* **Product author**: Sendinblue
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: high (8.1)


## Description

In sendinblue module for PrestaShop up to 4.0.14, a sensitive SQL call on `ajaxOrderTracking.php` can be executed with a trivial http call and exploited to forge a blind SQL injection throught for instance the POST or GET submitted `id_shop_group` variable if the double optin option is set.

**WARNING** : be warn that this module construct its token on PS_SHOP_NAME which is a bad practice since we have at least one other module in the ecosystem which expose this token on front. This is why we consider "Privilege required" to NONE instead of LOW.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: high
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)


## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails


## Patch

For PrestaShop 1.6, with sendinblue version 2.8.8, apply this patch:

```diff
--- a/modules/sendinblue/ajaxOrderTracking.php
+++ b/modules/sendinblue/ajaxOrderTracking.php
@@ -59,7 +59,7 @@ if ($sendin_order_track_status == 0) {
         $dateFormate = 'm-d-Y';
     }
     $condition = '';
-    $id_shop_group = !empty($id_shop_group) ? $id_shop_group : 'NULL';
+    $id_shop_group = !empty($id_shop_group) ? (int) $id_shop_group : 'NULL';
     $id_shop = !empty($id_shop) ? $id_shop : 'NULL';
     
     if ($id_shop === 'NULL' && $id_shop_group === 'NULL') {

```

For PrestaShop 1.7, with sendinblue version 4.x, *remove all files ajaxXXX.php* especially *ajaxOrderTracking.php*.


## Other recommandations

* It’s **highly recommended to upgrade the module** to the latest version or to **delete** the module if unused.
* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.


## Timeline

| Date | Action |
|--|--|
| 2022-12-02 | Issue discovered during a code reviews by 202 ecommerce |
| 2022-12-02 | Contact the author |
| 2023-12-19 | First fixed candidate from the author 4.0.15 for PrestaShop 1.7. PrestShop 1.6 remain vulnerable |
| 2022-12-19 | Contact the author to fix others vulnerabilities |
| 2023-01-31 | Contact PrestaShop team to claim a fix on all available package downloadable |
| 2023-02-12 | Request a CVE ID |
| 2023-07-23 | Publication of the CVE |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/newsletter-sms/8300-sendinblue-all-in-one-marketing-tool.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-26859)
