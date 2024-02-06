---
layout: post
title: "[CVE-2024-24303] Improper neutralization of SQL parameter in HiPresta - Gift Wrapping Pro module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,hiadvancedgiftwrapping"
severity: "critical (9.8)"
---

In the module "Gift Wrapping Pro" (hiadvancedgiftwrapping) up to version 1.4.0 from HiPresta for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2024-24303]
* **Published at**: 2023-02-06
* **Platform**: PrestaShop
* **Product**: hiadvancedgiftwrapping
* **Impacted release**: <= 1.4.0 (1.4.1 fixed the vulnerability)
* **Product author**: HiPresta
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `HiAdvancedGiftWrappingGiftWrappingModuleFrontController::addGiftWrappingCartValue()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

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


## Patch from 1.4.0

```diff
--- 1.4.0/modules/hiadvancedgiftwrapping/controllers/front.php
+++ 1.4.1/modules/hiadvancedgiftwrapping/controllers/front.php
...
        if ($gift && $selected_product) {
            Db::getInstance()->execute('
                UPDATE '._DB_PREFIX_.'cart
                SET gift = 1, gift_message = \'' . pSQL(Tools::getValue('gift_message')) . '\'
-               WHERE id_cart = '.Tools::getValue('id_cart'));
+               WHERE id_cart = '.(int) Tools::getValue('id_cart'));
        } else {
            Db::getInstance()->execute('
                UPDATE '._DB_PREFIX_.'cart
                SET gift = 0, gift_message = \'\'
-               WHERE id_cart = '.Tools::getValue('id_cart'));
+               WHERE id_cart = '.(int) Tools::getValue('id_cart'));
        }
...
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **hiadvancedgiftwrapping**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-09-19 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-09-19 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-09-19 | PrestaShop Addons security Team confirm versions scope |
| 2023-11-21 | Author provide a patch |
| 2024-02-05 | Received CVE ID |
| 2024-02-06 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/registration-ordering-process/31464-gift-wrapping-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-24303)