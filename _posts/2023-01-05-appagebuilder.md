---
layout: post
title: "[CVE-2022-22897] Major updates > SQL Injections in PrestaShop appagebuilder module up to 2.4.5"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,appagebuilder"
severity: "critical (9.8)"
---

PrestaShop Ap Pagebuilder module versions 2.4.5 and below suffer from several remote SQL injection vulnerability.


## Summary

* **CVE ID**: [CVE-2022-22897](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22897)
* **Published at**: 2022-09-25
* **Updated at**: 2023-01-05
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: appagebuilder
* **Impacted release**: <=2.4.5
* **Product author**: apollotheme / leo theme
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

On AP PAGEBUILDER PrestaShop module <= 2.4.5 contents many improper neutralization parameters including 'product_all_one_img' and 'image_product'.

**WARNING** : Be aware that versions from 2.0.0 to 2.4.3+ (exact release is not determined) own another sql injection which will certainly bypass your WAF (base64 payloads) so you should upgrade asap to 2.4.5.


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

* Obtain admin access
* Technical and personal data leaks

## Proof of concept

Initial [POC](https://packetstormsecurity.com/files/168148/PrestaShop-Ap-Pagebuilder-2.4.4-SQL-Injection.html)

```bash
curl -v 'https://localhost/modules/appagebuilder/apajax.php?rand=1641313272327&leoajax=1&product_all_one_img=1)+or+sleep(4)%23&image_product=0&wishlist_compare=1'
curl -v 'hhttp://localhost/modules/appagebuilder/apajax.php?rand=1641313272327&leoajax=1&product_all_one_img=1&image_product=1)+or+sleep(4)%23&wishlist_compare=1'
```

New POCs

```bash 
curl -v 'https://localhost/modules/appagebuilder/apajax.php?leoajax=1&product_manufacture=1,1)+or+sleep(4)%23--'
```

POC which bypass WAF is not supplied.

## Patch

Disclamer: These patches are based on available known versions installed on PrestaShop. 
This advisory try to do its best to be useful for everyone who want to fix critical vulnerabilities.

### Release 2.4.5

```diff
--- a/apajax.php
+++ b/apajax.php
@@ -71,7 +71,7 @@ if (Tools::getValue('leoajax') == 1) {
 					FROM `'._DB_PREFIX_.'product` p
 					'.Shop::addSqlAssociation('product', 'p').'
 					LEFT JOIN `'._DB_PREFIX_.'category_product` cp ON p.`id_product` = cp.`id_product`
-					WHERE cp.`id_category` IN ('.$list_cat.')
+					WHERE cp.`id_category` IN ('.implode(', ', array_map('intval', explode(',', $list_cat))).')
 				AND product_shop.`visibility` IN ("both", "catalog")
 				AND product_shop.`active` = 1
 				GROUP BY cp.`id_category`';
@@ -84,6 +84,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($leo_pro_cdown) {
         $leo_pro_cdown = explode(',', $leo_pro_cdown);
         $leo_pro_cdown = array_unique($leo_pro_cdown);
+        $leo_pro_cdown = array_map('intval', $leo_pro_cdown); // fix sql injection
         $leo_pro_cdown = implode(',', $leo_pro_cdown);
         $result['pro_cdown'] = $module->hookProductCdown($leo_pro_cdown);
     }
@@ -91,6 +92,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($leo_pro_color) {
         $leo_pro_color = explode(',', $leo_pro_color);
         $leo_pro_color = array_unique($leo_pro_color);
+        $leo_pro_color = array_map('intval', $leo_pro_color); // fix sql injection
         $leo_pro_color = implode(',', $leo_pro_color);
         $result['pro_color'] = $module->hookProductColor($leo_pro_color);
     }
@@ -99,6 +101,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($product_list_image) {
         $product_list_image = explode(',', $product_list_image);
         $product_list_image = array_unique($product_list_image);
+        $product_list_image = array_map('intval', $product_list_image); // fix sql injection
         $product_list_image = implode(',', $product_list_image);
 
         # $leocustomajax = new Leocustomajax();
@@ -107,6 +110,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($product_one_img) {
         $product_one_img = explode(',', $product_one_img);
         $product_one_img = array_unique($product_one_img);
+        $product_one_img = array_map('intval', $product_one_img); // fix sql injection
         $product_one_img = implode(',', $product_one_img);
 
         $result['product_one_img'] = $module->hookProductOneImg($product_one_img);

--- a/appagebuilder.php
+++ b/appagebuilder.php
@@ -2887,7 +3050,7 @@ class APPageBuilder extends Module imple
     {
         $where = '';
         if (strpos($manuid, ',') !== false) {
-            $where = ' WHERE `id_manufacturer` IN(' . $manuid . ')';
+            $where = ' WHERE `id_manufacturer` IN(' . implode(', ', array_map('intval', explode(',', $manuid))) . ')';
         } else {
             $where = ' WHERE `id_manufacturer` = ' . (int) $manuid;
         }
@@ -2937,7 +3100,7 @@ class APPageBuilder extends Module imple
         $link = new Link($protocol_link, $protocol_content);
 
         $id_lang = Context::getContext()->language->id;
-        $where = ' WHERE i.`id_product` IN ('.$list_pro.') AND (ish.`cover`=0 OR ish.`cover` IS NULL) AND ish.`id_shop` = '.Context::getContext()->shop->id;
+        $where = ' WHERE i.`id_product` IN ('.implode(', ', array_map('intval', explode(',', $list_pro))).') AND (ish.`cover`=0 OR ish.`cover` IS NULL) AND ish.`id_shop` = '.Context::getContext()->shop->id;
         $order = ' ORDER BY i.`id_product`,`position`';
         $limit = ' LIMIT 0,1';
         //get product info 
@@ -2973,7 +3136,7 @@ class APPageBuilder extends Module imple
 
         $id_lang = Context::getContext()->language->id;
         $image_product = Tools::getValue('image_product');
-        $where = ' WHERE i.`id_product` IN ('.$list_pro.') AND i.`id_image` NOT IN ('.$image_product.') AND ish.`id_shop` = '.Context::getContext()->shop->id;
+        $where = ' WHERE i.`id_product` IN ('.implode(', ', array_map('intval', explode(',', $list_pro))).') AND i.`id_image` NOT IN ('.implode(', ', array_map('intval', explode(',', $image_product))).') AND ish.`id_shop` = '.Context::getContext()->shop->id;
         $order = ' ORDER BY i.`id_product`,`position`';
         $limit = ' LIMIT 0,1';
         //get product info
      }
```

### Release 2.0.x to 2.3.x

```diff
--- a/apajax.php
+++ b/apajax.php
@@ -111,6 +111,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($leo_pro_cdown) {
         $leo_pro_cdown = explode(',', $leo_pro_cdown);
         $leo_pro_cdown = array_unique($leo_pro_cdown);
+        $leo_pro_cdown = array_map('intval', $leo_pro_cdown); // fix sql injection
         $leo_pro_cdown = implode(',', $leo_pro_cdown);
         $result['pro_cdown'] = $module->hookProductCdown($leo_pro_cdown);
     }
@@ -118,6 +119,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($leo_pro_color) {
         $leo_pro_color = explode(',', $leo_pro_color);
         $leo_pro_color = array_unique($leo_pro_color);
+        $leo_pro_color = array_map('intval', $leo_pro_color); // fix sql injection
         $leo_pro_color = implode(',', $leo_pro_color);
         $result['pro_color'] = $module->hookProductColor($leo_pro_color);
     }
@@ -125,9 +127,10 @@ if (Tools::getValue('leoajax') == 1) {
     if ($product_list_image) {
         $product_list_image = explode(',', $product_list_image);
         $product_list_image = array_unique($product_list_image);
+        $product_list_image = array_map('intval', $product_list_image); // fix sql injection
         $product_list_image = implode(',', $product_list_image);
 
         # $leocustomajax = new Leocustomajax();
         $result['product_list_image'] = $module->hookProductMoreImg($product_list_image);
     }
     
@@ -135,6 +139,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($product_one_img) {
         $product_one_img = explode(',', $product_one_img);
         $product_one_img = array_unique($product_one_img);
+        $product_one_img = array_map('intval', $product_one_img); // fix sql injection
         $product_one_img = implode(',', $product_one_img);
 
         $result['product_one_img'] = $module->hookProductOneImg($product_one_img);
@@ -142,6 +147,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($product_attribute_one_img) {
         $product_attribute_one_img = explode(',', $product_attribute_one_img);
         $product_attribute_one_img = array_unique($product_attribute_one_img);
+        $product_attribute_one_img = array_map('intval', $product_attribute_one_img); // fix sql injection
         $product_attribute_one_img = implode(',', $product_attribute_one_img);
 
         $result['product_attribute_one_img'] = $module->hookProductAttributeOneImg($product_attribute_one_img);
@@ -149,7 +155,8 @@ if (Tools::getValue('leoajax') == 1) {
     if ($product_all_one_img) {
         $product_all_one_img = explode(',', $product_all_one_img);
         $product_all_one_img = array_unique($product_all_one_img);
+        $product_all_one_img = array_map('intval', $product_all_one_img); // fix sql injection
         $product_all_one_img = implode(',', $product_all_one_img);
 
         $result['product_all_one_img'] = $module->hookProductAllOneImg($product_all_one_img);
     }

@@ -71,7 +71,7 @@ if (Tools::getValue('leoajax') == 1) {
 					FROM `'._DB_PREFIX_.'product` p
 					'.Shop::addSqlAssociation('product', 'p').'
 					LEFT JOIN `'._DB_PREFIX_.'category_product` cp ON p.`id_product` = cp.`id_product`
-					WHERE cp.`id_category` IN ('.$list_cat.')
+					WHERE cp.`id_category` IN ('.implode(', ', array_map('intval', explode(',', $list_cat))).')
 				AND product_shop.`visibility` IN ("both", "catalog")
 				AND product_shop.`active` = 1
 				GROUP BY cp.`id_category`';

--- a/appagebuilder.php
+++ b/appagebuilder.php
@@ -2033,7 +2033,7 @@ class APPageBuilder extends Module
 		LEFT JOIN `'._DB_PREFIX_.'product_comment_grade` pcg ON (pcg.`id_product_comment` = pc.`id_product_comment`)
 		LEFT JOIN `'._DB_PREFIX_.'product_comment_criterion` pcc ON (pcc.`id_product_comment_criterion` = pcg.`id_product_comment_criterion`)
 		LEFT JOIN `'._DB_PREFIX_.'product_comment_criterion_lang` pccl ON (pccl.`id_product_comment_criterion` = pcg.`id_product_comment_criterion`)
-		WHERE pc.`id_product` in ('.$list_product.')
+		WHERE pc.`id_product` in ('.implode(', ', array_map('intval', explode(',', $list_product))).')
 		AND pccl.`id_lang` = '.(int)$id_lang.
                         ($validate == '1' ? ' AND pc.`validate` = 1' : '')));
     }
@@ -2050,7 +2050,7 @@ class APPageBuilder extends Module
         $result = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS('
 		SELECT COUNT(pc.`id_product`) AS nbr, pc.`id_product` 
 		FROM `'._DB_PREFIX_.'product_comment` pc
-		WHERE `id_product` in ('.$list_product.')'.($validate == '1' ? ' AND `validate` = 1' : '').'
+		WHERE `id_product` in ('.implode(', ', array_map('intval', explode(',', $list_product))).')'.($validate == '1' ? ' AND `validate` = 1' : '').'
 		AND `grade` > 0 GROUP BY pc.`id_product`');
         return $result;
     }
@@ -2118,7 +2118,7 @@ class APPageBuilder extends Module
         $link = new Link($protocol_link, $protocol_content);
 
         $id_lang = Context::getContext()->language->id;
-        $where = ' WHERE i.`id_product` IN ('.$list_pro.') AND (ish.`cover`=0 OR ish.`cover` IS NULL) AND ish.`id_shop` = '.Context::getContext()->shop->id;
+        $where = ' WHERE i.`id_product` IN ('.implode(', ', array_map('intval', explode(',', $list_pro))).') AND (ish.`cover`=0 OR ish.`cover` IS NULL) AND ish.`id_shop` = '.Context::getContext()->shop->id;
         $order = ' ORDER BY i.`id_product`,`position`';
         $limit = ' LIMIT 0,1';
         //get product info
```

### 1.0.0 

```diff
--- a/apajax.php
+++ b/apajax.php
@@ -57,7 +57,7 @@ if (Tools::getValue('leoajax') == 1) {
                     FROM `'._DB_PREFIX_.'product` p
                     '.Shop::addSqlAssociation('product', 'p').'
                     LEFT JOIN `'._DB_PREFIX_.'category_product` cp ON p.`id_product` = cp.`id_product`
-                    WHERE cp.`id_category` IN ('.$list_cat.')
+                    WHERE cp.`id_category` IN ('.implode(', ', array_map('intval', explode(',', $list_cat))).')
                 AND product_shop.`visibility` IN ("both", "catalog")
                 AND product_shop.`active` = 1
                 GROUP BY cp.`id_category`';
@@ -70,6 +70,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($leo_pro_cdown) {
         $leo_pro_cdown = explode(',', $leo_pro_cdown);
         $leo_pro_cdown = array_unique($leo_pro_cdown);
+        $leo_pro_cdown = array_map('intval', $leo_pro_cdown);
         $leo_pro_cdown = implode(',', $leo_pro_cdown);
         $result['pro_cdown'] = $module->hookProductCdown($leo_pro_cdown);
     }
@@ -77,6 +78,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($leo_pro_color) {
         $leo_pro_color = explode(',', $leo_pro_color);
         $leo_pro_color = array_unique($leo_pro_color);
+        $leo_pro_color = array_map('intval', $leo_pro_color);
         $leo_pro_color = implode(',', $leo_pro_color);
         $result['pro_color'] = $module->hookProductColor($leo_pro_color);
     }
@@ -85,6 +87,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($leo_pro_info) {
         $leo_pro_info = explode(',', $leo_pro_info);
         $leo_pro_info = array_unique($leo_pro_info);
+        $leo_pro_info = array_map('intval', $leo_pro_info);
         $leo_pro_info = implode(',', $leo_pro_info);
 
         # $leocustomajax = new Leocustomajax();
@@ -93,6 +96,7 @@ if (Tools::getValue('leoajax') == 1) {
     if ($leo_pro_add) {
         $leo_pro_add = explode(',', $leo_pro_add);
         $leo_pro_add = array_unique($leo_pro_add);
+        $leo_pro_add = array_map('intval', $leo_pro_add);
         $leo_pro_add = implode(',', $leo_pro_add);
 
         $result['pro_add'] = $module->hookProductOneImg($leo_pro_add);

--- a/appagebuilder..php
+++ b/appagebuilder..php
@@ -1160,12 +1160,12 @@ class APPageBuilder extends Module
             $id_categories = isset($params['categorybox']) ? $params['categorybox'] : '';
             if (isset($params['category_type']) && $params['category_type'] == 'default') {
                 $where .= ' AND product_shop.`id_category_default` '.(strpos($id_categories, ',') === false ?
-                                '= '.(int)$id_categories : 'IN ('.$id_categories.')');
+                                '= '.(int)$id_categories : 'IN ('.implode(', ', array_map('intval', explode(',', $id_categories))).')');
             } else {
                 $sql_join .= ' INNER JOIN '._DB_PREFIX_.'category_product cp		ON (cp.id_product= p.`id_product` )';
                 
                 $where .= ' AND cp.`id_category` '.(strpos($id_categories, ',') === false ?
-                                '= '.(int)$id_categories : 'IN ('.$id_categories.')');
+                                '= '.(int)$id_categories : 'IN ('.implode(', ', array_map('intval', explode(',', $id_categories))).')');
 
                 $sql_group = ' GROUP BY p.id_product';
 
@@ -1174,7 +1174,7 @@ class APPageBuilder extends Module
         $value_by_supplier = isset($params['value_by_supplier']) ? $params['value_by_supplier'] : 0;
         if ($value_by_supplier && isset($params['supplier'])) {
             $id_suppliers = $params['supplier'];
-            $where .= ' AND p.id_supplier '.(strpos($id_suppliers, ',') === false ? '= '.(int)$id_suppliers : 'IN ('.$id_suppliers.')');
+            $where .= ' AND p.id_supplier '.(strpos($id_suppliers, ',') === false ? '= '.(int)$id_suppliers : 'IN ('.implode(', ', array_map('intval', explode(',', $id_suppliers))).')');
         }
         $value_by_product_id = isset($params['value_by_product_id']) ? $params['value_by_product_id'] : 0;
         if ($value_by_product_id && isset($params['product_id'])) {
@@ -1185,13 +1185,13 @@ class APPageBuilder extends Module
             }
 
             $product_id = implode(',', $temp);
-            $where .= ' AND p.id_product '.(strpos($product_id, ',') === false ? '= '.(int)$product_id : 'IN ('.$product_id.')');
+            $where .= ' AND p.id_product '.(strpos($product_id, ',') === false ? '= '.(int)$product_id : 'IN ('.implode(', ', array_map('intval', explode(',', $product_id))).')');
         }
 
         $value_by_manufacture = isset($params['value_by_manufacture']) ? $params['value_by_manufacture'] : 0;
         if ($value_by_manufacture && isset($params['manufacture'])) {
             $id_manufactures = $params['manufacture'];
-            $where .= ' AND p.id_manufacturer '.(strpos($id_manufactures, ',') === false ? '= '.(int)$id_manufactures : 'IN ('.$id_manufactures.')');
+            $where .= ' AND p.id_manufacturer '.(strpos($id_manufactures, ',') === false ? '= '.(int)$id_manufactures : 'IN ('.implode(', ', array_map('intval', explode(',', $id_manufactures))).')');
         }
         $product_type = isset($params['product_type']) ? $params['product_type'] : '';
         $value_by_product_type = isset($params['value_by_product_type']) ? $params['value_by_product_type'] : 0;
@@ -1272,6 +1272,7 @@ class APPageBuilder extends Module
 //            $sql .= ' ORDER BY product_shop.date_add '.(!$get_total ? ' LIMIT '.(int)$n : '');
             $sql .= ' ORDER BY RAND() '.(!$get_total ? ' LIMIT '.(int)$n : '');
         } else {
+            $order_way = Validate::isOrderWay($order_way) ? Tools::strtoupper($order_way) : 'ASC';
             $sql .= ' ORDER BY '.(!empty($order_by_prefix) ? $order_by_prefix.'.' : '').'`'.bqSQL($order_by).'` '.pSQL($order_way)
                     .(!$get_total ? ' LIMIT '.(((int)$p - 1) * (int)$n).','.(int)$n : '');
         }
@@ -1752,16 +1753,18 @@ class APPageBuilder extends Module
         if ($params['order_by'] == 'position') {
             $params['order_by'] = 'id_manufacturer';
         }
+	     $params['order_by'] = Validate::isOrderBy($params['order_by']) ? $params['order_by'] : 'id_manufacturer';
         if (isset($params['order_way']) && $params['order_way'] == 'random') {
             $order = ' RAND()';
         } else {
+	         $params['order_way'] = Validate::isOrderWay($params['order_way']) ? $params['order_way'] : 'DESC';
             $order = (isset($params['order_by']) ? ' '.$params['order_by'] : '').(isset($params['order_way']) ? ' '.$params['order_way'] : '');
         }
         $sql = 'SELECT m.*, ml.`description`, ml.`short_description`
 			FROM `'._DB_PREFIX_.'manufacturer` m
 			'.Shop::addSqlAssociation('manufacturer', 'm').'
 			INNER JOIN `'._DB_PREFIX_.'manufacturer_lang` ml ON (m.`id_manufacturer` = ml.`id_manufacturer` AND ml.`id_lang` = '.(int)$id_lang.')
-			WHERE m.`active` = 1 '.(isset($params['manuselect']) ? 'AND m.`id_manufacturer` IN ('.$params['manuselect'].')' : '').' 
+			WHERE m.`active` = 1 '.(isset($params['manuselect']) ? 'AND m.`id_manufacturer` IN ('.implode(',',array_map('intval',explode(',',$params['manuselect']))).')' : '').' 
 			ORDER BY '.$order;
         $manufacturers = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS($sql);
         if ($manufacturers === false) {
@@ -1848,7 +1851,7 @@ class APPageBuilder extends Module
 		LEFT JOIN `'._DB_PREFIX_.'product_comment_grade` pcg ON (pcg.`id_product_comment` = pc.`id_product_comment`)
 		LEFT JOIN `'._DB_PREFIX_.'product_comment_criterion` pcc ON (pcc.`id_product_comment_criterion` = pcg.`id_product_comment_criterion`)
 		LEFT JOIN `'._DB_PREFIX_.'product_comment_criterion_lang` pccl ON (pccl.`id_product_comment_criterion` = pcg.`id_product_comment_criterion`)
-		WHERE pc.`id_product` in ('.$list_product.')
+		WHERE pc.`id_product` in ('.implode(',',array_map('intval',explode(',',$list_product))).')
 		AND pccl.`id_lang` = '.(int)$id_lang.
                         ($validate == '1' ? ' AND pc.`validate` = 1' : '')));
     }
```

## Other recommandations

* We highly recommand to remove from your server this module if not used, or upgrade to the latest release of the module **appagebuilder** up to 2.4.5 and apply all fixes mentionned above.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.


## Links

* [Author product page](https://apollotheme.com/products/ap-pagebuilder-prestashop-module)
* [PrestaShop marketplace product page](https://addons.prestashop.com/en/page-customization/20111-ap-page-builder.html)
* [POC](https://packetstormsecurity.com/files/168148/PrestaShop-Ap-Pagebuilder-2.4.4-SQL-Injection.html)
* [Partial patch](https://blog.leotheme.com/security-issue-with-the-module-appagebuilder-v-2-2-4.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2022-22897)
