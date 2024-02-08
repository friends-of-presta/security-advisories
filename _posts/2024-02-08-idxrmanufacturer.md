---
layout: post
title: "[CVE-2023-46350] Improper neutralization of SQL parameter in InnovaDeluxe - Manufacturer or supplier alphabetical search module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,idxrmanufacturer"
severity: "critical (9.8)"
---

In the module "Manufacturer or supplier alphabetical search" (idxrmanufacturer) up to version 2.0.4 from InnovaDeluxe for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-46350](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46350)
* **Published at**: 2024-02-08
* **Platform**: PrestaShop
* **Product**: idxrmanufacturer
* **Impacted release**: <= 2.0.4 (2.0.5 fixe the vulnerability)
* **Product author**: InnovaDeluxe
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The methods `IdxrmanufacturerFunctions::getCornersLink`, `IdxrmanufacturerFunctions::getManufacturersLike` and `IdxrmanufacturerFunctions::getSuppliersLike` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch from 2.0.3

```diff
--- 2.0.3/modules/idxrmanufacturer/classes/module/Functions.php
+++ XXXXX/modules/idxrmanufacturer/classes/module/Functions.php
@@ -241,7 +241,7 @@ trait IdxrmanufacturerFunctions
         $query->select('cor.id_corners, corl.link_rewrite ');
         $query->from('corners', 'cor');
         $query->innerJoin('corners_lang', 'corl', 'cor.id_corners = corl.id_corners');
-        $query->where('m.name like \'%'.Tools::getValue('q').'%\'');
+        $query->where('m.name like \'%'.pSQL(Tools::getValue('q')).'%\'');
         $query->where('cor.id_' . $listing . ' = ' . (int) $id);
         $query->orderBy('m.`name` ASC');
         if ($row = Db::getInstance()->getRow($query)) {
@@ -270,7 +270,7 @@ trait IdxrmanufacturerFunctions
         $query->from('manufacturer', 'm');
         $query->join(Shop::addSqlAssociation('manufacturer', 'm'));
         $query->leftJoin('manufacturer_lang', 'ml', 'm.id_manufacturer = ml.id_manufacturer AND ml.id_lang = ' . (int) $id_lang);
-        $query->where('m.name like \'%'.Tools::getValue('q').'%\'');
+        $query->where('m.name like \'%'.pSQL(Tools::getValue('q')).'%\'');
         $query->where('m.active = 1');
         $query->orderBy('m.`name` ASC');
         return Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS($query);
@@ -284,7 +284,7 @@ trait IdxrmanufacturerFunctions
         $query->from('supplier', 's');
         $query->leftJoin('supplier_lang', 'sl', 's.`id_supplier` = sl.`id_supplier` AND sl.`id_lang` = ' . (int) $id_lang);
         $query->join(Shop::addSqlAssociation('supplier', 's'));
-        $query->where('s.name like \'%'.Tools::getValue('q').'%\'');
+        $query->where('s.name like \'%'.pSQL(Tools::getValue('q')).'%\'');
         $query->orderBy('s.`name` ASC');

         return Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS($query);

```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **idxrmanufacturer**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-09-17 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-09-17 | Contact Author to confirm versions scope by author |
| 2023-09-18 | Author confirm versions scope by author |
| 2023-10-12 | Author provide patch |
| 2023-10-23 | Received CVE ID |
| 2024-02-08 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/search-filters/19166-manufacturer-or-supplier-alphabetical-search.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-46350)
