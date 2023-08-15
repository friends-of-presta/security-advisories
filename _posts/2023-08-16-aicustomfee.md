---
layout: post
title: "[CVE-2023-33663] Improper neutralization of a SQL parameter in aicustomfee from ai-dev module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,aicustomfee"
severity: "critical (9.8)"
---

In the module "Customization fields fee for your store" (aicustomfee) for PrestaShop, an attacker can perform SQL injection up to 0.2.0. Release 0.2.1 fixed this security issue.

## Summary

* **CVE ID**: [CVE-2023-33663](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33663)
* **Published at**: 2023-08-16
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: aicustomfee
* **Impacted release**: < 0.2.1 (0.2.1 fixed issue)
* **Product author**: ai-dev / @ide-info
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Before 0.2.1, sensitives SQL calls in file `includes/ajax.php` can be executed with a trivial http call and exploited to forge a blind SQL injection throught the POST or GET submitted `data` and `product` variables.


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

* Technical and personal data leaks
* Obtain admin access
* Remove all data of the linked PrestaShop
* Display sensitives tables to front-office to unlock potential admin's ajax scripts of modules protected by token on the ecosystem


## Patch

```diff
--- a/modules/aicustomfee/includes/ajax.php
+++ b/modules/aicustomfee/includes/ajax.php
switch (Tools::getValue('action')) {
    case 'cloneCombination':
        if (!($data = Tools::getValue('data')) || !($combination = Tools::getValue('combination')) || !($product = Tools::getValue('product'))) {
            die();
        }
            
        $data = explode('|', $data);
+       $data = array_map('intval', $data);
        $result = Db::getInstance()->getRow(
            'SELECT COUNT(id_product_attribute) AS number, id_product_attribute FROM '._DB_PREFIX_.'product_attribute_combination WHERE id_attribute IN ('.implode(',', $data).') GROUP BY id_product_attribute HAVING number = '.count($data)
        );
        
--- a/modules/aicustomfee/includes/functions.php
+++ b/modules/aicustomfee/includes/functions.php
    public function createCombination($product, $old_combination, $data) 
    {
        //    Add for Prestashop 1.5 version and above
        if ((float)Tools::substr(_PS_VERSION_, 0, 3) >= 1.5) {
            $shop_id = (int)Shop::getContextShopGroupID();
        }
+       $product = (int) $product;
+       $old_combination = (int) $old_combination;
+       $data = array_map('intval', $data);
        //    Get the product data
        $product_data = Db::getInstance()->getRow('SELECT * FROM '._DB_PREFIX_.'product WHERE id_product = '.$product);
```


## Other recommandations

* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.



## Timeline

| Date | Action |
|--|--|
| 2023-05-08 | Vunlnerability found during a audit by [202 ecommerce](https://www.202-ecommerce.com/) |
| 2023-05-10 | Contact the author |
| 2023-05-12 | The author confirm the issue and supply a fixed release |
| 2023-05-12 | Request a CVE ID |
| 2023-08-16 | Publication of this advisory |


## Links

* [Author product page](https://www.boutique.ai-dev.fr/en/customization/62-customization-fee.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-33663)

