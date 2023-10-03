---
layout: post
title: "[CVE-2023-43983] Improper neutralization of SQL parameter in Presto Changeo - Attribute Grid module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,attributegrid"
severity: "critical (9.8)"
---

In the module "Attribute Grid" (attributegrid) from Presto Changeo for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-43983](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43983)
* **Published at**: 2023-10-03
* **Platform**: PrestaShop
* **Product**: attributegrid
* **Impacted release**: < 2.0.3 [SEE NOTE BELOW]
* **Product author**: Presto Changeo
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Ajax scripts disable_json.php has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

Note : Author refuse to help us to fix the version scope since its module are no longer supported. This vulnerability has been seen in versions up to version 1.6.7 and no longer exists in version 2.0.3. We do not have versions > 1.6.7 and < 2.0.3, so it's impossible for us to certify that these versions are or not are impacted by this vulnerability.

**WARNING** : Author discontinue support of its module so you should no longer continue to use them.

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

## Patch from 1.6.7

```diff
--- 1.6.7/modules/attributegrid/disable_json.php
+++ XXXXX/modules/attributegrid/disable_json.php
...
		LEFT JOIN `'._DB_PREFIX_.'product_attribute_combination` pac ON pac.`id_product_attribute` = pa.`id_product_attribute`
		'.($ps_version >= 1.5?Shop::addSqlAssociation('product_attribute', 'pa'):'').'
-		WHERE pa.`id_product` in ('.$_POST['products'].')';
+		WHERE pa.`id_product` in ('.implode(',', array_map('intval', explode(',', $_POST['products']))).')';
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **attributegrid**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-08-01 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-08-01 | Contact Author to confirm versions scope by author |
| 2023-08-01 | Author replied us that he do not have time since support is ended |
| 2023-08-27 | Recontact Author to confirm versions scope by author |
| 2023-08-27 | Author replied us to stop communicating with him |

## Links

* [Author product page](https://www.presto-changeo.com/prestashop/prestashop-17-modules/122-prestashop-attribute-grid-module.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-43983)
