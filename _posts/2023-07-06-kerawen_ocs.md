---
layout: post
title: "[CVE-2023-27845] Improper neutralization of a SQL parameter in KerAwen Omnichannel Stocks module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,kerawen_ocs"
severity: "critical (9.8)"
---

In the module "KerAwen Omnichannel Stocks" (kerawen_ocs) for PrestaShop, an anonymous user can perform SQL injection before 1.4.1. Release 1.4.1 fixed this security issue.


## Summary

* **CVE ID**: [CVE-2023-27845](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27845)
* **Published at**: 2023-07-06
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: kerawen_ocs
* **Impacted release**: < 1.4.1
* **Product author**: KerAwen
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Up to 1.3.7.1, multiple sensitive SQL calls in class `KerawenHelper::setCartOperationInfo()` and  `KerawenHelper::resetCheckoutSessionData()` can be executed with a trivial http call and exploited to forge a blind SQL injection throught the POST or GET submitted "ocs_id_cart" or "ocs_checkout_session_data" variable.

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
* Copy/paste data from sensitive tables to FRONT to exposed tokens and unlock admins' ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch

Sample of patch. We recommend to upgrade this module to fix all sensitive SQL calls.

```diff
--- a/modules/kerawen_ocs/classes/KerawenHelper.php
+++ b/modules/kerawen_ocs/classes/KerawenHelper.php
@@ -3622,23 +3622,23 @@ class KerawenHelper
     public static function setCartOperationInfo($id_cart, $data)
     {
         $current_date_time = date('Y-m-d H:i:s');
-        $temp_sql = 'SELECT * FROM `' . _DB_PREFIX_ . self::$_TABLE_NAME_CART_OPERATION_INFO . '` WHERE  id_cart = '.pSQL($id_cart);
+        $temp_sql = 'SELECT * FROM `' . _DB_PREFIX_ . self::$_TABLE_NAME_CART_OPERATION_INFO . '` WHERE  id_cart = '. (int) $id_cart;
         $temp_result = Db::getInstance()->executeS($temp_sql);
         if (!empty($temp_result) && count($temp_result) >0) {
             // update
             $upd_sql = 'UPDATE `' . _DB_PREFIX_ . self::$_TABLE_NAME_CART_OPERATION_INFO . '` SET `data`= "' . pSQL($data) . '" ,`date_update`="' . pSQL($current_date_time) . '"
-                WHERE id_cart =' . pSQL($id_cart) . ';';
+                WHERE id_cart =' .  (int) $id_cart . ';';
             Db::getInstance()->execute($upd_sql);
         } else {
             // insert
-            $insert_sql_debug = 'INSERT INTO `' . _DB_PREFIX_ . self::$_TABLE_NAME_CART_OPERATION_INFO . '` ( `id_cart`, `data`, `date_add`, `date_update`) VALUES  ( '.pSQL($id_cart).', "' . pSQL($data) . '","' . pSQL($current_date_time) . '","' . pSQL($current_date_time) . '");';
+            $insert_sql_debug = 'INSERT INTO `' . _DB_PREFIX_ . self::$_TABLE_NAME_CART_OPERATION_INFO . '` ( `id_cart`, `data`, `date_add`, `date_update`) VALUES  ( '. (int) $id_cart.', "' . pSQL($data) . '","' . pSQL($current_date_time) . '","' . pSQL($current_date_time) . '");';
             Db::getInstance()->execute($insert_sql_debug);
         }
     }
 
     public static function getCartOperationInfo($id_cart)
     {
-        $temp_sql = 'SELECT * FROM `' . _DB_PREFIX_ . self::$_TABLE_NAME_CART_OPERATION_INFO . '` WHERE  id_cart = '.pSQL($id_cart);
+        $temp_sql = 'SELECT * FROM `' . _DB_PREFIX_ . self::$_TABLE_NAME_CART_OPERATION_INFO . '` WHERE  id_cart = '. (int) $id_cart;
         $temp_result = Db::getInstance()->executeS($temp_sql);
         if (!empty($temp_result) && count($temp_result) >0) {
             return $temp_result[0]['data'];
```

## Other recommandations

* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-11-23 | Vunlnerability found during a audit by [202 ecommerce](https://www.202-ecommerce.com/) |
| 2022-11-23 | Contact the author |
| 2023-02-12 | Request a CVE ID |
| 2023-02 | Fix published by the author |
| 2023-03-07 | New vunerability found |
| 2023-05 | Fix published by the author |
| 2023-07-06 | Publication of this advisory |

## Links

* [Product page](https://kerawen.com/logiciel-de-caisse/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-27845)

