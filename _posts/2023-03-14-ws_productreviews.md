---
layout: post
title: "[CVE-2023-25206] Multiple improper neutralization of SQL parameters in ws_productreviews module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ws_productreviews"
severity: "critical (9.8)"
---

In the module "Advanced Reviews: Photos, Reminder, Google Snippets" (ws_productreviews), an anonymous user can perform SQL injection in affected versions. 3.6.2 fixed vulnerabilities.

## Summary

* **CVE ID**: [CVE-2023-25206](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-25206)
* **Published at**: 2023-03-14
* **Advisory source**: Friends-of-Presta.org
* **Vendor**: PrestaShop
* **Product**: ws_productreviews
* **Impacted release**: < 3.6.2
* **Product author**: Anastasia
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: high (9.8)

## Description

In ws_productreviews module for PrestaShop up to 3.6.2, multiple sensitives SQL calls in class `ProductReviews::getByProduct()` (or method `getLastReviews()`, `getByValidate()`, `ProductReviews::getByValidate()`, ...) can be executed with a trivial http call and exploited to forge a blind SQL injection.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Technical and personal data leaks
* Obtain admin access
* Remove all data of the linked PrestaShop
* Display sensitives tables to front-office to unlock potential admin's ajax scripts of modules protected by token on the ecosystem

## Proof of concept

```bash
curl -v 'https://domain.tld/module/ws_productreviews/default?r_sort=date_add%60%3BSELECT%20SLEEP%2825%29%23'
curl -v 'https://domain.tld/module/ws_productreviews/default?action=getList&r_sort=date_add%60%3BSELECT%20SLEEP%2825%29%23'
```

## Patch

```diff
--- a/ProductReviews.php
+++ b/ProductReviews.php
@@ -106,6 +106,9 @@ class ProductReviews extends ObjectModel
      */
     public static function getByProduct($id_product, $start = 1, $step = 5, $sort = 'date_add', $filtre = false, $id_customer = null)
     {
+        if (!Validate::isOrderBy($sort)) {
+            $sort = 'date_add';
+        }
         if (!Validate::isUnsignedId($id_product)) {
             return false;
         }
@@ -124,7 +127,7 @@ class ProductReviews extends ObjectModel
             LEFT JOIN `'._DB_PREFIX_.'customer` c ON c.`id_customer` = pc.`id_customer`
             WHERE pc.`id_product` = '.(int)($id_product).($validate == '1' ? ' AND pc.`validate` = 1' : '').($filtre ? ' AND pc.`grade` = '.$filtre : '').'
             AND pc.`id_shop` = '.(int)Context::getContext()->shop->id.' 
-                    ORDER BY pc.`'.$sort.'` DESC 
+                    ORDER BY pc.`'.bqSQL($sort).'` DESC 
             LIMIT '.(int)($start).' ,'.(int)($step)
             );
             
@@ -135,26 +138,11 @@ class ProductReviews extends ObjectModel
 
     public static function getLastReviews($start = 1, $step = 5, $sort = 'date_add', $id_customer = null, $id_category = false)
     {
+        if (!Validate::isOrderBy($sort)) {
+            $sort = 'date_add';
+        }
         $validate = Configuration::get('WS_PRODUCTREVIEWS_MODERATE');     
         $reviews = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS(
             'SELECT pc.`id_product_comment`, pc.`str_img_name`, pc.`id_product`, pl.`name`, pc.`ip`, pc.`recommend`, pc.`id_customer`,
             (SELECT count(*) FROM `'._DB_PREFIX_.'ws_product_comment_usefulness` pcu WHERE pcu.`id_product_comment` = pc.`id_product_comment` AND pcu.`usefulness` = 1) as total_useful,
@@ -170,7 +158,7 @@ die();
             ($validate == '1' ? ' pc.`validate` = 1' : '1').
                 ' AND pc.`id_shop` = '.(int)Context::getContext()->shop->id.
                 ($id_category != false ? ' AND cp.`id_category` = '.(int) $id_category : ' ').
-                ' ORDER BY pc.`'.$sort.'` DESC 
+                ' ORDER BY pc.`'.bqSQL($sort).'` DESC 
             LIMIT '.(int)($start).' ,'.(int)($step)
         );
         
@@ -436,7 +424,7 @@ die();
             WHERE `id_product` = '.(int)($id_product).
                     ($validate == '1' ? ' AND `validate` = 1' : '').
                     ' AND pc.`id_shop` = '.(int)Context::getContext()->shop->id.
-                    ($r_filtre ? ' AND pc.`grade` = '.$r_filtre : ''));
+                    ($r_filtre ? ' AND pc.`grade` = "'.pSQL($r_filtre) : '"'));
 
         return  $result;
     }
@@ -489,6 +477,12 @@ die();
      */
     public static function getByValidate($validate = '0', $deleted = false, $sort = 'date_add', $sort_way = 'DESC', $filters = false)
     {
+        if (!Validate::isOrderBy($sort)) {
+            $sort = 'date_add';
+        }
+        if (!Validate::isOrderWay($sort_way)) {
+            $sort_way = 'DESC';
+        }
         $sql  = '
             SELECT pc.`id_product_comment`, pc.`id_product`, pc.`ip`, pc.`str_img_name`, IF(c.id_customer, CONCAT(c.`firstname`, \' \',  c.`lastname`), pc.customer_name) customer_name, pc.`title`, pc.`content`, pc.`grade`, pc.`date_add`, pc.`respond`, pc.`recommend`,    
                 v.`id_voucher`, pl.`name`
@@ -504,13 +498,13 @@ die();
                     $key = Tools::substr($key, 7);
                     if ($key == 'date_add') {
                         if ($value[0] != null) {
-                            $sql  .= ' AND pc.`'.$key.'` >= "'.$value[0].'" ';
+                            $sql  .= ' AND pc.`'.bqSQL($key).'` >= "'.pSQL($value[0]).'" ';
                         }
                         if ($value[1] != null) {
-                            $sql  .= ' AND pc.`'.$key.'` <= "'.$value[1].'" ';
+                            $sql  .= ' AND pc.`'.bqSQL($key).'` <= "'.pSQL($value[1]).'" ';
                         }
                     } else {
-                        $sql  .= ' AND '.$key.' = "'.$value.'" ';
+                        $sql  .= ' AND `'.bqSQL($key).' = "'.pSQL($value).'" ';
                     }
                 }
             }
@@ -554,6 +548,12 @@ die();
      */
     public static function getAll($sort = 'date_add', $sort_way = 'DESC', $filters = false)
     {
+        if (!Validate::isOrderBy($sort)) {
+            $sort = 'date_add';
+        }
+        if (!Validate::isOrderWay($sort_way)) {
+            $sort_way = 'DESC';
+        }
         $sql  = '
         SELECT pc.`id_product_comment`, pc.`id_product`, pc.`str_img_name`, pc.`ip`, IF(c.id_customer, CONCAT(c.`firstname`, \' \',  c.`lastname`), pc.customer_name) customer_name, pc.`title`, pc.`content`, pc.`grade`, pc.`date_add`, pl.`name`
         FROM `'._DB_PREFIX_.'ws_product_comment` pc
@@ -567,18 +567,17 @@ die();
                     $key = Tools::substr($key, 7);
                     if ($key == 'date_add') {
                         if ($value[0] != null) {
-                            $sql  .= ' AND pc.`'.$key.'` >= "'.$value[0].'" ';
+                            $sql  .= ' AND pc.`'.bqSQL($key).'` >= "'.pSQL($value[0]).'" ';
                         }
                         if ($value[1] != null) {
-                            $sql  .= ' AND pc.`'.$key.'` <= "'.$value[1].'" ';
+                            $sql  .= ' AND pc.`'.bqSQL($key).'` <= "'.pSQL($value[1]).'" ';
                         }
                     } else {
-                        $sql  .= ' AND '.$key.' = "'.$value.'" ';
+                        $sql  .= ' AND '.bqSQL($key).'`= "'.pSQL($value).'" ';
                     }
                 }
             }
         }
-        
         if (!$sort) {
             $sql .= ' ORDER BY `date_add` DESC ';
         } elseif ($sort == 'location') {
```

## Other recommandations

* It’s recommended to upgrade the module beyong 3.6.2.
* Upgrade PrestaShop beyong 1.7.8.8 (and 8.0.1) to disable multiquery executions (separated by ";").
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skilled because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-12-20 | Issue discovered during a code reviews by 202 ecommerce |
| 2022-12-20 | Contact the author |
| 2023-01-11 | First fixed candidate from the author 3.6.1 |
| 2022-01-11 | Contact the author to fix others vulnerabilities |
| 2023-01-26 | Last fixes from the author |
| 2023-02-01 | Request a CVE ID |
| 2023-03-14 | Publication of this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/customer-reviews/22373-advanced-reviews-photos-reminder-google-snippets.html)
* [National Vulnerability Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-25206)
