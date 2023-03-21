---
layout: post
title: "[CVE-2023-27637][CVE-2023-27638][CWE-89] Improper neutralization of SQL parameters in module Prestashop Custom Product Designer (tshirtecommerce) for PrestaShop"
categories: module
author:
- Profileo.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,tshirtecommerce"
severity: "high (9.8)"
---

In the module Custom Product Designer (tshirtecommerce), an anonymous user can perform an SQL injection attack. The vulnerability is actively exploited by bots. As the module doesn't seems to be maintained since 2019, it's strongly suggested to remove it.

## Summary

* **CVE ID**: CVE-2023-27637 / CVE-2023-27638
* **Published at**: 2023-03-21
* **Advisory source**: Friends-Of-Presta
* **Vendor**: PrestaShop
* **Product**: tshirtecommerce
* **Impacted release**: <= 2.1.4 (latest version)
* **Product author**: Tshirtecommerce Team
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8) // based on CVSS base metrics

## Description

The following issues have been seen in the last version of the Prestashop Custom Product Designer (tshirtecommerce) module for PrestaShop, published on July 24, 2019 (not fixed up to date) :
- an HTTP request can be forged with a compromised product_id GET parameter in order to exploit an insecure parameter in front controller file `designer.php`, which could lead to a SQL injection.
- and we also suspect that an HTTP request can be potentially forged with a compromised tshirtecommerce_design_cart_id GET parameter in order to exploit an insecure parameter in function `hookActionCartSave` and `updateCustomizationTable`, which could eventually lead to a SQL injection.

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
* Copy/past datas from sensibles tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijacked emails

## Proof of concept

```bash
https://example.com/module/tshirtecommerce/designer?product_id=900982561&parent_id=1;SELECT%20SLEEP(5);
```

## Patch 

Due to the number of vulnerabilities discovered, we advise removing the module and `tshirtecommerce` directory in root directory.
Patches listed below concerns the two SQL injections discovered.

```diff
--- a/modules/tshirtecommerce/controllers/front/designer.php
+++ b/modules/tshirtecommerce/controllers/front/designer.php
@@ -105,7 +105,7 @@ class TshirtecommerceDesignerModuleFrontController extends ModuleFrontController
                        $content = '<div class="row-designer"></div>';
 
                        // Get data from ps_product table
-                       $settings = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS("SELECT `design_product_id` FROM `"._DB_PREFIX_."product` WHERE `id_product`=".$parent_id);
+                       $settings = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS("SELECT `design_product_id` FROM `"._DB_PREFIX_."product` WHERE `id_product`='".pSQL($parent_id)."'");
 
                if (isset($settings[0]) && isset($settings[0]['design_product_id'])) {
                     $design_product_id = $settings[0]['design_product_id'];
```

```diff
--- a/modules/tshirtecommerce/tshirtecommerce.php 
+++ b/modules/tshirtecommerce/tshirtecommerce.php 
@@ -1775,8 +1775,8 @@ class Tshirtecommerce extends Module
        protected function updateCustomizationTable($id_customization, $id_address_delivery, $id_cart, $id_product, $tdci, $tdt = 'cart')
        {
                Db::getInstance()->update('customization', array(
-                       'tshirtecommerce_design_cart_id'=> $tdci,
-                       'tshirtecommerce_design_type'   => $tdt),
+                       'tshirtecommerce_design_cart_id'=> pSQL($tdci),
+                       'tshirtecommerce_design_type'   => pSQL($tdt)),
                        '`id_customization`                     = '.(int)$id_customization.' AND
                        `id_address_delivery`                   = '.(int)$id_address_delivery.' AND
                        `id_cart`                                               = '.(int)$id_cart.' AND
```

## Timeline

If the CVE is published by Friends of Presta.

| Date | Action |
| -- | -- |
| 2022-10-23 | First detection in Apache logs of an exploitation of this module |
| 2023-03-04 | Discovery of the vulnerability by Profileo |
| 2023-03-04 | Contacting the editor tshirtecommerce (no reply) |
| 2023-03-04 | Contacting codecanyon / envato market (no reply) |
| 2023-03-07 | Email reminder to the editor tshirtecommerce (no reply) |
| 2023-03-07 | Email reminder to the editor tshirtecommerce by another channel (no reply) |
| 2023-03-09 | Email reminder to the editor tshirtecommerce (no reply) |
| 2023-03-16 | Email reminder to the editor tshirtecommerce (no reply) + Contact form in tshirtecommerce site (not working) |
| 2023-03-16 | Contacting again codecanyon / envato market |
| 2023-03-21 | Publish this security advisory |

## Other recommandations

* It’s recommended to completely remove the tshirtecommerce module as long as the module is not updated
* Upgrade PrestaShop beyond 1.7.8.8 (and 8.0.1) to disable multiquery executions (separated by ";").
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skilled because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [Module Custom Product Designer (tshirtecommerce)](https://codecanyon.net/item/prestashop-custom-product-designer/19202018)
* [Editor Website : T-Shirt eCommerce](https://tshirtecommerce.com/)
* [National Vulnerability Database CVE-2023-27639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27639)
* [National Vulnerability Database CVE-2023-27640](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27640)