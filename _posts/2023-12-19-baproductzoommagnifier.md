---
layout: post
title: "[CVE-2023-50027] Improper neutralization of SQL parameter in Buy Addons - Best Zoom Magnifier Effect - BAZoom Magnifier module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,baproductzoommagnifier"
severity: "critical (9.8)"
---

In the module "Best Zoom Magnifier Effect - BAZoom Magnifier" (baproductzoommagnifier) up to version 1.0.16 from Buy Addons for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-50027](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50027)
* **Published at**: 2023-12-19
* **Platform**: PrestaShop
* **Product**: baproductzoommagnifier
* **Impacted release**: <= 1.0.16 (1.0.17 fixed the vulnerability)
* **Product author**: Buy Addons
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `BaproductzoommagnifierZoomModuleFrontController::run()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards.

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
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails


## Proof of concept

```bash
curl -v -d "fc=module&module=baproductzoommagnifier&controller=zoom&id_langs=1';select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--" 'https://preprod.X/'
```

## Patch from 1.0.16

```diff
--- 1.0.16/modules/baproductzoommagnifier/controllers/front/zoom.php
+++ XXXXXX/modules/baproductzoommagnifier/controllers/front/zoom.php
...
        $id_lang = Tools::getValue('id_langs');
        $id_shop = Tools::getValue('id_shop');
        $name_product = Tools::getValue('name_product');
        $db = Db::getInstance(_PS_USE_SQL_SLAVE_);
        $search = "Select " . _DB_PREFIX_ . "product_lang.id_product," . _DB_PREFIX_ . "product_lang.name from ";
        $search .= _DB_PREFIX_ . "product INNER JOIN " . _DB_PREFIX_ . "product_lang ON " ;
        $search .= _DB_PREFIX_ . "product_lang.id_product=";
        $search .= _DB_PREFIX_ . "product.id_product WHERE ";
        $search .= _DB_PREFIX_ . "product_lang.name like '%".pSQL($name_product)."%'";
-       $search .=" AND id_lang='$id_lang' AND id_shop = '".(int) $id_shop."'";
+       $search .=" AND id_lang=" . (int) $id_lang . " AND id_shop = " . (int) $id_shop;
...
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **baproductzoommagnifier**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-09-30 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-09-30 | Contact Author to confirm versions scope by author |
| 2023-09-30 | Author confirms version scope |
| 2023-11-20 | Author provide a patch |
| 2023-11-28 | Request a CVE ID |
| 2023-12-12 | Received CVE ID |
| 2023-12-19 | Publish this security advisory |

## Links

* [Author product page](https://buy-addons.com/store/prestashop/module/product-page/best-zoom-magnifier-effect-bazoom-magnifier.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-50027)
