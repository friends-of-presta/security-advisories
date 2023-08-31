---
layout: post
title: "[CVE-2023-27637][CVE-2023-27638][CWE-89] Improper neutralization of SQL parameters in module PrestaShop Custom Product Designer (tshirtecommerce) for PrestaShop"
categories: module
author:
- Profileo.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,tshirtecommerce"
severity: "critical (9.8)"
---

In the module Custom Product Designer (tshirtecommerce), an anonymous user can perform an SQL injection attack. The vulnerability is actively exploited by bots. As the module doesn't seems to be maintained since 2019, it's strongly suggested to remove it.

## Summary

* **CVE ID**: [CVE-2023-27637](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27637) / [CVE-2023-27638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27638)
* **Published at**: 2023-03-21
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: tshirtecommerce
* **Impacted release**: <= 2.1.4 (latest version)
* **Product author**: Tshirtecommerce Team
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The following issues have been seen in the last version of the PrestaShop Custom Product Designer (tshirtecommerce) module for PrestaShop, published on July 24, 2019 (not fixed up to date) :
- an HTTP request can be forged with a compromised product_id GET parameter in order to exploit an insecure parameter in front controller file `designer.php`, which could lead to a SQL injection.
- and we also suspect that an HTTP request can be potentially forged with a compromised tshirtecommerce_design_cart_id GET parameter in order to exploit an insecure parameter in function `hookActionCartSave` and `updateCustomizationTable`, which could eventually lead to a SQL injection.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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
+                       $settings = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS("SELECT `design_product_id` FROM `"._DB_PREFIX_."product` WHERE `id_product`=".(int)$parent_id);
 
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

## Other recommendations

* It’s recommended to completely remove the tshirtecommerce module as long as the module is not updated
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

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

## Links

* [Module Custom Product Designer (tshirtecommerce)](https://codecanyon.net/item/prestashop-custom-product-designer/19202018)
* [Editor Website : T-Shirt eCommerce](https://tshirtecommerce.com/)
* [National Vulnerability Database CVE-2023-27637](https://nvd.nist.gov/vuln/detail/CVE-2023-27637)
* [National Vulnerability Database CVE-2023-27638](https://nvd.nist.gov/vuln/detail/CVE-2023-27638)
