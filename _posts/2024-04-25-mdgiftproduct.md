---
layout: post
title: "[CVE-2024-33268] Improper neutralization of SQL parameter in Digincube - Free Gifts Products module for PrestaShop"
categories: modules
author:
- realdev.fr
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,mdgiftproduct"
severity: "critical (9.8)"
---

In the module "Free Gifts Products" (mdgiftproduct) up to version 1.4.1 from Digincube for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2024-33268](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33268)
* **Published at**: 2024-04-25
* **Platform**: PrestaShop
* **Product**: mdgiftproduct
* **Impacted release**: < 1.4.1 (1.4.1 fixed the vulnerability)
* **Product author**: Digincube
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `MdGiftRule::addGiftToCart()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

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


## Patch from 1.3.9

```diff
--- 1.3.9/modules/mdgiftproduct/classes/models/MdGiftRule.php
+++ XXXXX/modules/mdgiftproduct/classes/models/MdGiftRule.php
        $insert_product_discount = [];
        if (!empty($products)) {
            foreach ($products as $productItem) {
-               $productItemAttribut = isset($productItem['id_product_attribute']) ? $productItem['id_product_attribute'] : 0;
+               $productItemAttribut = isset($productItem['id_product_attribute']) ? (int) $productItem['id_product_attribute'] : 0;
                if ($auto) {
                    $productItem['qty'] = $nb_product == 1 ? (int)$this->nb_product_gift : 1;
                }
                $productItem_qty = isset($productItem['qty']) ? (int)$productItem['qty'] : 1;

                $cart->updateQty($productItem_qty, $productItem['id_product'], $productItemAttribut, false, 'up');
                $hashData = uniqid().$this->id .'_'. $cart->id . '_' . $productItem['id_product']. '_' . $productItemAttribut;
                $values_hash = md5($hashData);
                //$insert_product_discount[] = '('.(int)$cart->id.','.(int)$this->id.','.(int)$productItem['id_product'].','.$productItemAttribut.','.($nb_product == 1 ? (int)$this->nb_product_gift : 1).', "'.$values_hash.'" )';

                $insert_product_discount[] = '('.(int)$cart->id.','.(int)$this->id.','.(int)$productItem['id_product'].','.$productItemAttribut.','.$productItem_qty.', "'.$values_hash.'" )';
            }
        }
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **mdgiftproduct**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2024-01-12 | Issue discovered during a code review by [realdev](https://www.realdev.fr) and [TouchWeb.fr](https://www.touchweb.fr) |
| 2024-01-12 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2024-01-12 | PrestaShop Addons security Team confirms version scope by author |
| 2024-03-24 | Author provide a patch |
| 2024-04-23 | Received CVE ID |
| 2024-04-25 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/promotions-cadeaux/52163-cadeaux-produits-gratuits.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-33268)