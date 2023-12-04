---
layout: post
title: "[CVE-2023-40920] Improper neutralization of an SQL parameter in prixanconnect module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,prixanconnect"
severity: "critical (9.8)"
---

In the module "Prixan connect" (prixanconnect) for PrestaShop, an attacker can perform a blind SQL injection before 1.62 without restrictions. Release 1.62 fixed this security issue.

## Summary

* **CVE ID**: [CVE-2023-40920](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-40920)
* **Published at**: 2023-10-05
* **Advisory source**: Friends-Of-Presta.org
* **Vendor**: PrestaShop
* **Product**: prixanconnect
* **Impacted release**: <= 1.61 (1.62 fixed the issue)
* **Product author**: Prixan
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Up to Release 1.63, multiple sensitive SQL calls in class `PrixanconnectUpdateProductsModuleFrontController::importProducts()` can be executed with a trivial http call and exploited to forge a blind SQL injection throught a json string posted in the body content.


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


## Patch

```diff
--- a/prixanconnect/controllers/front/Products.php
+++ b/prixanconnect/controllers/front/Products.php
@@ -33,21 +33,21 @@ class PrixanconnectProductsModuleFrontCo
          LEFT JOIN `" . _DB_PREFIX_ . "product_attribute` AS pa ON pa.`id_product_attribute` = pashop.`id_product_attribute`
          LEFT JOIN `" . _DB_PREFIX_ . "product_attribute_combination` AS combi ON combi.`id_product_attribute` = pashop.`id_product_attribute`
          LEFT JOIN `" . _DB_PREFIX_ . "attribute` as attr ON attr.`id_attribute` = combi.`id_attribute`
-         LEFT JOIN `" . _DB_PREFIX_ . "attribute_lang` as attlang ON attlang.`id_attribute` = attr.`id_attribute` AND attlang.`id_lang` = " . $langID . "
+         LEFT JOIN `" . _DB_PREFIX_ . "attribute_lang` as attlang ON attlang.`id_attribute` = attr.`id_attribute` AND attlang.`id_lang` = " . (int)$langID . "
          LEFT JOIN `" . _DB_PREFIX_ . "attribute_group_lang`AS grouplang ON grouplang.`id_attribute_group` = attr.`id_attribute_group` AND grouplang.`id_lang` = attlang.`id_lang`
-         WHERE prshop.`id_shop` = " . $idShop;
+         WHERE prshop.`id_shop` = " . (int)$idShop;
         if ($only_active === 1) {
             $query .= " AND prshop.`active` = 1";
         }
         if (!empty($date_from)) {
-            $query .= " AND prshop.`date_upd` > '$date_from'";
+            $query .= ' AND prshop.`date_upd` > "'.pSQL($date_from).'"';
         }
 
         if (!empty($product_ids) && count($product_ids) > 0) {
-            $query .= ' AND prshop.`id_product` IN (' . join(',', $product_ids) . ') ';
+            $query .= ' AND prshop.`id_product` IN (' . implode(',', array_map('intval', $product_ids)) . ') ';
         }

+        if(!empty($limit)) {
+             if (Tools::getValue('start') != null && Tools::getValue('limit') != null) {
+               $limit = ' LIMIT ' . (int) Tools::getValue('start') . ', ' . (int) Tools::getValue('limit');
+           } else if (Tools::getValue('limit') != null) {
+               $limit = ' LIMIT ' . (int) Tools::getValue('limit');
+           } else {
+               $limit = '';
+           }
+       }
        $query .= " ORDER BY prshop.`id_product`  $limit";
 
         return $query;
     }

@@ -177,21 +157,12 @@ INNER JOIN `" . _DB_PREFIX_ . "orders` O
         WHERE pt.name = \"product\" GROUP BY  p.id_object ) view_counter on (view_counter.obj_id=producttable.`id_product`) ";

         $mainSqlQuery = "SELECT producttable.id_product, od.sales_count,od.sales,od.purchase_cost FROM 
         `" . _DB_PREFIX_ . "product` AS producttable
                INNER JOIN  `" . _DB_PREFIX_ . "product_shop` AS prshop  ON producttable.`id_product`= prshop.`id_product`
                 INNER JOIN $sqlSubQuerySalesCount
-        WHERE prshop.`active` = 1 AND prshop.`id_shop` = " . $idShop;
-
-        //   LEFT JOIN $sqlSubQueryViews
+        WHERE prshop.`active` = 1 AND prshop.`id_shop` = " . (int)$idShop;
 
-        // $mainSqlQuery = $this->parseDateAndAddToSqlQuery($mainSqlQuery, 'start_date', '>=', false);
-        // $mainSqlQuery = $this->parseDateAndAddToSqlQuery($mainSqlQuery, 'end_date', '<=', true);
 
         if (Tools::getValue('ids') != null) {
             $splitted = explode(',', Tools::getValue('ids'));

--- a/prixanconnect/controllers/front/ProductsStats.php
+++ b/prixanconnect/controllers/front/ProductsStats.php
@@ -177,66 +161,25 @@ INNER JOIN `" . _DB_PREFIX_ . "orders` O
         WHERE pt.name = \"product\" GROUP BY  p.id_object ) view_counter on (view_counter.obj_id=producttable.`id_product`) ";
         $mainSqlQuery = "SELECT producttable.id_product, od.sales_count,od.sales,od.purchase_cost, view_counter.views FROM 
         `" . _DB_PREFIX_ . "product` AS producttable
                INNER JOIN  `" . _DB_PREFIX_ . "product_shop` AS prshop  ON producttable.`id_product`= prshop.`id_product`
                 INNER JOIN $sqlSubQuerySalesCount
                LEFT JOIN $sqlSubQueryViews
-        WHERE prshop.`active` = 1 AND prshop.`id_shop` = " . $idShop;
+        WHERE prshop.`active` = 1 AND prshop.`id_shop` = " . (int)$idShop;
 
         if (Tools::getValue('ids') != null) {
             $splitted = explode(',', Tools::getValue('ids'));
             if (count($splitted) > 0) {
-                $mainSqlQuery .= ' AND producttable.id_product IN (' . implode(',', $splitted) . ')';
+                $mainSqlQuery .= ' AND producttable.id_product IN (' . implode(',', array_map('intval', $splitted)) . ')';
             }
         }

--- a/prixanconnect/controllers/front/ProductsViews.php
+++ b/prixanconnect/controllers/front/ProductsViews.php
@@ -176,7 +160,7 @@ class PrixanconnectProductsViewsModuleFr
         `" . _DB_PREFIX_ . "product` AS producttable
                INNER JOIN  `" . _DB_PREFIX_ . "product_shop` AS prshop  ON producttable.`id_product`= prshop.`id_product`
                LEFT JOIN $sqlSubQueryViews
-        WHERE prshop.`active` = 1 AND prshop.`id_shop` = " . $idShop;
+        WHERE prshop.`active` = 1 AND prshop.`id_shop` = " . (int)$idShop;

@@ -184,7 +168,7 @@ class PrixanconnectProductsViewsModuleFr
         if (Tools::getValue('ids') != null) {
             $splitted = explode(',', Tools::getValue('ids'));
             if (count($splitted) > 0) {
-                $mainSqlQuery .= ' AND producttable.id_product IN (' . implode(',', $splitted) . ')';
+                $mainSqlQuery .= ' AND producttable.id_product IN (' . implode(',', array_map('intval', $splitted)) . ')';
             }
         }

--- a/prixanconnect/controllers/front/UpdateProducts.php
+++ b/prixanconnect/controllers/front/UpdateProducts.php
@@ -16,18 +16,20 @@ class PrixanconnectUpdateProductsModuleF
     {
         header('Content-type: application/json');
         // $request->getContent();
+
         die(Tools::jsonEncode(array('check' => 'you must call this url with POST method')));
+        
     }
     private function getProductAttributes($product_id)
     {
-        $query = "SELECT id_product_attribute FROM `" . _DB_PREFIX_ . "product_attribute` WHERE id_product=" . $product_id;
+        $query = "SELECT id_product_attribute FROM `" . _DB_PREFIX_ . "product_attribute` WHERE id_product=" . (int)$product_id;
 
         $results = Db::getInstance()->executeS($query);
         return $results;
     }
     private function getProductFromAttributeId($product_attribute_id)
     {
-        $query = "SELECT id_product FROM `" . _DB_PREFIX_ . "product_attribute` WHERE id_product_attribute=" . $product_attribute_id;
+        $query = "SELECT id_product FROM `" . _DB_PREFIX_ . "product_attribute` WHERE id_product_attribute=" . (int)$product_attribute_id;
 
         $results = Db::getInstance()->executeS($query);
         if ($results && count($results) > 0) {

@@ -102,20 +80,14 @@ class PrixanconnectUpdateProductsModuleF

     private function changeProductAttributePrice_mode_impact($id_product, $id_product_attribute, $price, $id_shop)
     {
-        $query = 'SELECT price FROM  `' . _DB_PREFIX_ . 'product` WHERE id_product=' . $id_product;
+        $query = 'SELECT price FROM  `' . _DB_PREFIX_ . 'product` WHERE id_product=' . (int)$id_product;
         $price_result =    Db::getInstance()->executeS($query);
 
         if ($price_result == null || count($price_result) == 0) {
@@ -127,16 +99,11 @@ class PrixanconnectUpdateProductsModuleF
         //only shop
-        $query = 'UPDATE `' . _DB_PREFIX_ . 'product_attribute_shop` SET price=' . $impact_price . ' WHERE id_product_attribute=' . $id_product_attribute;
+        $query = 'UPDATE `' . _DB_PREFIX_ . 'product_attribute_shop` SET price=' . (float) $impact_price . ' WHERE id_product_attribute=' . (int)$id_product_attribute;
         if (!empty($id_shop)) {
-            $query .= ' AND id_shop=' . $id_shop;
+            $query .= ' AND id_shop=' . (int)$id_shop;
         }
 
 
@@ -147,18 +114,17 @@ class PrixanconnectUpdateProductsModuleF
         if (empty($id_shop)) {
             $id_shop = 0;
         }
-        $query = 'INSERT INTO `' . _DB_PREFIX_ . 'specific_price` (id_product,id_product_attribute,price,`from`,`to`,id_shop) VALUES(' . (int) $id_product . ',' . $id_product_attribute . ',' . $price . ',' . "'0000-00-00 00:00:00'" . ',' . "'0000-00-00 00:00:00'" . ',' .  $id_shop . ')';
+        $query = 'INSERT INTO `' . _DB_PREFIX_ . 'specific_price` (id_product,id_product_attribute,price,`from`,`to`,id_shop) VALUES(' . (int) $id_product . ',' . (int) $id_product_attribute . ',' . (float) $price . ',' . "'0000-00-00 00:00:00'" . ',' . "'0000-00-00 00:00:00'" . ',' .  (int) $id_shop . ')';
         return  Db::getInstance()->execute($query);
 
-        // $query = "UPDATE `" . _DB_PREFIX_ . "specific_price` SET `from`='1980-01-01 00:00:00', `to`='2100-01-01 00:00:00' WHERE `id_specific_price`=" . $newSpecId;
-        // return   Db::getInstance()->executeS($query);
+
     }
     private function deleteSpecificPriceForAttribute($id_product, $id_product_attribute, $id_shop)
     {
         if (empty($id_shop)) {
             $id_shop = 0;
         }
-        $query = 'DELETE FROM `' . _DB_PREFIX_ . 'specific_price` WHERE `id_product` = ' . (int) $id_product . ' AND `id_product_attribute` = ' . $id_product_attribute . ' AND id_shop=' . $id_shop;
+        $query = 'DELETE FROM `' . _DB_PREFIX_ . 'specific_price` WHERE `id_product` = ' . (int) $id_product . ' AND `id_product_attribute` = ' . (int) $id_product_attribute . ' AND id_shop=' . (int)$id_shop;
         Db::getInstance()->execute($query);
     }
     private function updateProductPriceWithCleanSpecific($id, $prix_base, $prix_promo, $idShop)
@@ -195,15 +161,21 @@ class PrixanconnectUpdateProductsModuleF
     {
         header('Content-type: application/json');
         $returned = array('success' => false, 'products' => array(), 'error' => null);
+        
         try {
 
             $idShop = Tools::getValue('id_shop');

             if (!empty($idShop)) {
                 $idShop = (int)  $idShop;
             }
+            if (strtoupper(trim($_SERVER['REQUEST_METHOD'])) != 'POST'){
+                throw new Exception('you must call this url with POST method');
+            }
+            $cle_module = Configuration::get('PRIXANCONNECT_CLE');
+            if (Tools::getValue('key') == false || Tools::getValue('key') != $cle_module) {
+                throw new Exception('erreur d\'autorisation');
+            }
 
             // $entityBody = stream_get_contents(STDIN);
             $entityBody = file_get_contents('php://input');

@@ -298,10 +264,10 @@ class PrixanconnectUpdateProductsModuleF
                                         if (!is_numeric($prix_base)) {
                                             throw new Exception('prix_base is not correct');
                                         }
-                                        $query_result =  Db::getInstance()->executeS('update `' . _DB_PREFIX_ . 'pm_advancedpack` SET fixed_price=' . $prix_base  . ' WHERE id_pack=' . $id);
+                                        $query_result =  Db::getInstance()->executeS('update `' . _DB_PREFIX_ . 'pm_advancedpack` SET fixed_price=' . (float)$prix_base  . ' WHERE id_pack=' . (int)$id);
                                         $returned['products'][] = array('id' => $id, 'success' => $query_result);
                                     } else {
-                                        $query_result =  Db::getInstance()->executeS('update `' . _DB_PREFIX_ . 'pm_advancedpack` SET fixed_price=NULL WHERE id_pack=' . $id);
+                                        $query_result =  Db::getInstance()->executeS('update `' . _DB_PREFIX_ . 'pm_advancedpack` SET fixed_price=NULL WHERE id_pack=' . (int)$id);
                                         $returned['products'][] = array('id' => $id, 'success' => $query_result);
                                     }
                                 } else {
```

## Other recommandations

* It’s recommended to upgrade to the latest version of the module **prixanconnect**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-03-05 | Vulnerability discovered during a code reviews by [202 ecommerce](https://www.202-ecommerce.com/) |
| 2023-03-07 | Contact the author |
| 2023-04-05 | The author confirm the vulnerability without possibility to verify the patch |
| 2023-05-29 | Retrieve the patched release and ask to the author to fix all sensitive SQL calls |
| 2023-06-15 | Retry to contact Prixan team |
| 2023-08-15 | Request a CVE ID from Mitre.org |
| 2023-08-25 | Recieved the CVE ID |
| 2023-09-25 | Inform the author about the scheduled publication of the CVE. Propose 30 days of delay before disclose. |
| 2023-10-05 | Publication of this security advisory |


## Links

* [Product page](https://www.prixan.com/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-40920)

