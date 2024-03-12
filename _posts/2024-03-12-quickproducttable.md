---
layout: post
title: "[CVE-2024-28391] Improper neutralization of SQL parameter in FME Modules - Quick Order Form | Order Table module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 2dm.pl
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,quickproducttable"
severity: "critical (9.8)"
---

In the module "Quick Order Form | Order Table" (quickproducttable) up to version 1.2.1 from FME Modules for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2024-28391](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28391)
* **Published at**: 2024-03-12
* **Platform**: PrestaShop
* **Product**: quickproducttable
* **Impacted release**: <= 1.2.1 (1.3.0 fixed the vulnerability)
* **Product author**: FME Modules
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Methods `QuickProductTableFmmQuickModuleFrontController::readCsv()`, `QuickProductTableAjaxModuleFrontController::displayAjaxProductChangeAttr`, `QuickProductTableAjaxModuleFrontController::displayAjaxProductAddToCart`, `QuickProductTableAjaxModuleFrontController::getSearchProducts`, `QuickProductTableAjaxModuleFrontController::displayAjaxProductSku` has sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : One of exploits use a forged CSV so it will bypass most WAF.

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
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admin's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch from 1.2.1

```diff
--- 1.2.1/modules/quickproducttable/controllers/front/ajax.php
+++ 1.3.0/modules/quickproducttable/controllers/front/ajax.php
@@ -51,7 +51,7 @@ class QuickProductTableAjaxModuleFrontCo
         SELECT pac.`id_product_attribute`
         FROM `' . _DB_PREFIX_ . 'product_attribute_combination` pac
         INNER JOIN `' . _DB_PREFIX_ . 'product_attribute` pa ON pa.id_product_attribute = pac.id_product_attribute
-        WHERE id_product = ' . (int) $id_product . ' AND id_attribute IN (' . implode(',', $id_attributes) . ')
+        WHERE id_product = ' . (int) $id_product . ' AND id_attribute IN (' . implode(',', array_map('intval', $id_attributes)) . ')
         GROUP BY id_product_attribute
         HAVING COUNT(id_product) = ' . count($id_attributes));
         $price = Product::getPriceStatic($id_product, true, $id_product_attribute);
@@ -91,7 +91,7 @@ class QuickProductTableAjaxModuleFrontCo
         SELECT pac.`id_product_attribute`
         FROM `' . _DB_PREFIX_ . 'product_attribute_combination` pac
         INNER JOIN `' . _DB_PREFIX_ . 'product_attribute` pa ON pa.id_product_attribute = pac.id_product_attribute
-        WHERE id_product = ' . (int) $id_product . ' AND id_attribute IN (' . implode(',', $id_attributes) . ')
+        WHERE id_product = ' . (int) $id_product . ' AND id_attribute IN (' . implode(',', array_map('intval', $id_attributes)) . ')
         GROUP BY id_product_attribute
         HAVING COUNT(id_product) = ' . count($id_attributes));

@@ -193,7 +193,7 @@ class QuickProductTableAjaxModuleFrontCo
                 LEFT JOIN `' . _DB_PREFIX_ .
                 'image_lang` il ON (image_shop.`id_image` = il.`id_image` AND il.`id_lang` = ' .
         (int) $context->language->id . ')
-                WHERE p.id_product NOT IN (' . $enable_pro . ') AND p.id_category_default IN (' . $category . ')
+                WHERE p.id_product NOT IN (' . $enable_pro . ') AND p.id_category_default IN (' . implode(',', array_map('intval', explode(',', $category))) . ')
                 AND (pl.name LIKE \'%' . pSQL($query) . '%\' OR p.reference LIKE \'%' . pSQL($query) . '%\')' .
             (!empty($excludeIds) ? ' AND p.id_product NOT IN (' . $excludeIds . ') ' : ' ') .
             ($excludeVirtuals ? 'AND NOT EXISTS (SELECT 1 FROM `' . _DB_PREFIX_ .
@@ -493,7 +493,7 @@ class QuickProductTableAjaxModuleFrontCo
             $sql = new DbQuery();
             $sql->select('id_product');
             $sql->from('product');
-            $sql->where('reference = "' . $reference . '"');
+            $sql->where('reference = "' . pSQL($reference) . '"');
             $id_product = Db::getInstance()->getValue($sql);

```


```diff
--- 1.2.1/modules/quickproducttable/controllers/front/fmmquick.php
+++ 1.3.0/modules/quickproducttable/controllers/front/fmmquick.php
@@ -985,7 +985,7 @@ class QuickProductTableFmmQuickModuleFro
                 $sql = new DbQuery();
                 $sql->select('id_product');
                 $sql->from('product');
-                $sql->where('reference = "' . $reference . '"');
+                $sql->where('reference = "' . pSQL($reference) . '"');
                 $id_product = Db::getInstance()->getValue($sql);
                 $qty = (int) $key[1];
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **quickproducttable**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-09-02 | Issue discovered during a code review by [2DM](https://2dm.pl/) then [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-09-02 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-09-05 | PrestaShop Addons security Team confirms version scope by author |
| 2024-01-01 | Author provide a patch |
| 2024-03-11 | Received CVE ID |
| 2024-03-12 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/order-management/47933-quick-order-form-order-table.html)
* [Auhtor product page](https://www.fmemodules.com/en/prestashop-modules/171-prestashop-quick-frontend-product-update-price-quantity-status.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-28391)
