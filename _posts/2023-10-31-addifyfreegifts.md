---
layout: post
title: "[CVE-2023-44025] Improper neutralization of SQL parameter in Addify - Free Gifts module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,addifyfreegifts"
severity: "high (8.8)"
---

In the module "Free Gifts" (addifyfreegifts) up to version 1.0.2 from Addify for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-44025](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44025)
* **Published at**: 2023-10-31
* **Platform**: PrestaShop
* **Product**: addifyfreegifts
* **Impacted release**: <= 1.0.2 (1.2.0 fixed the vulnerability)
* **Product author**: Addify
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: high (8.8)

## Description

The method AddifyfreegiftsModel::getrulebyid() has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails


## Patch from 1.0.2

```diff
--- 1.0.2/modules/addifyfreegifts/controllers/front/addtocart.php
+++ XXXXX/modules/addifyfreegifts/controllers/front/addtocart.php
...
- $this->context->cookie->__set('Rule_Ids_manual', $id_rule);
+ $this->context->cookie->__set('Rule_Ids_manual', (int) $id_rule);
```

```diff
--- 1.0.2/modules/addifyfreegifts/classes/AddifyfreegiftsModel.php
+++ XXXXX/modules/addifyfreegifts/classes/AddifyfreegiftsModel.php
...
    public static function getrulebyid($rule_id, $check_group_id, $today)
    {
        $result = Db::getInstance()->executeS('
            SELECT *
-           FROM `'._DB_PREFIX_.'addifyfreegifts`WHERE rule_active = 1 AND id = '.$rule_id);
+           FROM `'._DB_PREFIX_.'addifyfreegifts`WHERE rule_active = 1 AND id = '. (int) $rule_id);
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **addifyfreegifts**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-08-03 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-08-03 | Contact PrestaShop Addons security Team to confirm version scope |
| 2023-08-03 | PrestaShop Addons security Team confirm version scope |
| 2023-09-18 | Author provide a patch |
| 2023-09-22 | Request a CVE ID |
| 2023-09-28 | Received CVE ID |
| 2023-10-31 | Publish this security advisory |

## Links

* [Author product page](https://addify.store/product/prestashop-free-gifts-module/)
* [PrestaShop addons product page](https://addons.prestashop.com/en/promotions-gifts/52140-free-gifts-buy-x-get-y-bogo-and-more.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-44025)
