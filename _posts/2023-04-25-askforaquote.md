---
layout: post
title: "[CVE-2023-27843] Improper neutralization of a SQL parameter in askforaquote module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,askforaquote"
severity: "critical (9.8)"
---

In the module "Ask for a Quote - Convert to order, messaging system" (askforaquote) for PrestaShop, an anonymous user can perform SQL injection before 5.4.3. Release 5.4.3 fixed this security issue.

## Summary

* **CVE ID**: [CVE-2023-27843](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27843)
* **Published at**: 2023-04-25
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: askforaquote
* **Impacted release**: < 5.4.3
* **Product author**: Presta FABRIQUE
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Up to 5.4.2, a sensitive SQL call in class `QuotesProduct::deleteProduct()` can be executed with a trivial http call and exploited to forge a blind SQL injection through the POST or GET submitted "item_id" variable.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Technical and personal data leaks
* Obtain admin access
* Remove all data of the linked PrestaShop
* Display sensitives tables to front-office to unlock potential admin’s ajax scripts of modules protected by token on the ecosystem

## Proof of concept

```bash
curl -v -X POST -d 'action=delete_from_cart&item_id=2_9%3Bdelete+from+0test+where+1%23' 'https://preprod.XXXXX/module/askforaquote/QuotesCart'
```

## Patch

```diff
--- v5.4.1/modules/askforaquote/classes/QuotesProduct.php
+++ v5.4.2/modules/askforaquote/classes/QuotesProduct.php
@@ -160,9 +160,9 @@ class QuotesProductCart extends ObjectMo
         $row = Db::getInstance()->getRow(
             'SELECT qp.`quantity`, qp.`id_product_attribute`
             FROM `' . _DB_PREFIX_ . 'quotes_product` qp
-            WHERE qp.`id_product` = ' . pSQL($id_product) . '
+            WHERE qp.`id_product` = ' . (int) $id_product . '
             AND qp.`id_quote` LIKE "' . pSQL($id_quote) . '"
-            AND qp.`id_product_attribute` = ' . pSQL($id_product_attribute)
+            AND qp.`id_product_attribute` = ' . (int) $id_product_attribute
         );
@@ -211,16 +211,16 @@ class QuotesProductCart extends ObjectMo
                 }
             }
 
-            if ((int)$current_qty < 0) {
+            if ((int) $current_qty < 0) {
                 return $this->deleteProduct($id_product, $row['id_product_attribute']);
             }
 
-            //update current product in cart
+            // update current product in cart
             $update = Db::getInstance()->execute(
                 'UPDATE `' . _DB_PREFIX_ . 'quotes_product`
-                SET `quantity` = ' . pSQL($current_qty) . ', `date_upd` = "' . pSQL(date('Y-m-d H:i:s', time())) . '"
-                WHERE `id_product` = ' . pSQL($id_product) . ' AND `id_quote` LIKE "' . pSQL($id_quote) .
-                '" AND `id_product_attribute` = ' . pSQL($id_product_attribute) . '
+                SET `quantity` = ' . (int) $current_qty . ', `date_upd` = "' . pSQL(date('Y-m-d H:i:s', time())) . '"
+                WHERE `id_product` = ' . (int) $id_product . ' AND `id_quote` LIKE "' . pSQL($id_quote) .
+                '" AND `id_product_attribute` = ' . (int) $id_product_attribute . '
                 LIMIT 1'
             );
@@ -543,15 +542,15 @@ class QuotesProductCart extends ObjectMo
         /* Product deletion */
         $result = Db::getInstance()->execute(
             'DELETE FROM `' . _DB_PREFIX_ . 'quotes_product`
-            WHERE `id_product` = ' . pSQL($id_product) . '
+            WHERE `id_product` = ' . (int) $id_product . '
             AND `id_quote` LIKE "' . pSQL($this->id_quote) . '"
-            AND `id_product_attribute` = ' . pSQL($id_product_attribute)
+            AND `id_product_attribute` = ' . (int) $id_product_attribute
         );
 
         if ($result) {
             return true;
         }
        //$this->update(true);
 
         return false;
     }
```

## Other recommendations

* It’s recommended to upgrade the module beyond 5.4.2.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skilled because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-10-09 | Issue discovered during a code review by 202 ecommerce and [TouchWeb](https://www.touchweb.fr) |
| 2023-02-12 | Request a CVE ID |
| 2023-02-28 | Contact the author |
| 2023-03-01 | The author confirm the issue |
| 2023-03-17 | Propose 30 days before disclosure |
| 2023-03-19 | The author confirm a fix release in progress |
| 2023-03-22 | The author published the release 5.4.2 |
| 2023-04-25 | Publication of this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/quotes/3725-ask-for-a-quote-convert-to-order-messaging-system.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-27843)
