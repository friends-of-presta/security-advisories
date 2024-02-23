---
layout: post
title: "[CVE-2023-50061] Improper neutralization of SQL parameter in Opart Easy Redirect for PrestaShop"
categories: modules
author:
- Opart
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,oparteasyredirect"
severity: "critical (9.8)"
---

In the module "Opart Easy Redirect" (oparteasyredirect) up to version 1.3.12 from Opart for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-50061](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50061)
* **Published at**: 2024-02-08
* **Platform**: PrestaShop
* **Product**: oparteasyredirect
* **Impacted release**: >= 1.3.8 and <= 1.3.12 (1.3.13 fixed the vulnerability)
* **Product author**: Opart
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Methods `Oparteasyredirect::hookActionDispatcher()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection on PHP 8.0- (so including PHP 7.X / 5.X).

The large scope of URL exposed to the vulnerability increases its severity and the risk that a pattern of URL is in whitelist of a WAF.

WARNING : This vulnerability will bypass some WAF, for this reason, POC is not given.

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


## Patch from 1.3.12

```diff
--- 1.3.12/modules/oparteasyredirect/oparteasyredirect.php
+++ 1.3.13/modules/oparteasyredirect/oparteasyredirect.php
@@ -384,3 +384,3 @@ class Oparteasyredirect extends Module
                                             INSERT INTO `'._DB_PREFIX_.'pagenotfound` (`request_uri`, `http_referer`, `date_add`, `id_shop`, `id_shop_group`)
-                        VALUES (\''.htmlentities($request_uri).'\', \''.htmlentities($http_referer).'\', NOW(), '.(int)$this->context->shop->id.', '.(int)$this->context->shop->id_shop_group.')
+                        VALUES (\''.pSQL(htmlentities($request_uri)).'\', \''.pSQL(htmlentities($http_referer)).'\', NOW(), '.(int)$this->context->shop->id.', '.(int)$this->context->shop->id_shop_group.')
                     '
@@ -406,3 +406,3 @@ class Oparteasyredirect extends Module
                                         INSERT INTO `'._DB_PREFIX_.'pagenotfound` (`request_uri`, `http_referer`, `date_add`, `id_shop`, `id_shop_group`)
-                    VALUES (\''.htmlentities($request_uri).'\', \''.htmlentities($http_referer).'\', NOW(), '.(int)$this->context->shop->id.', '.(int)$this->context->shop->id_shop_group.')
+                    VALUES (\''.pSQL(htmlentities($request_uri)).'\', \''.pSQL(htmlentities($http_referer)).'\', NOW(), '.(int)$this->context->shop->id.', '.(int)$this->context->shop->id_shop_group.')
                 '
@@ -427,3 +427,3 @@ class Oparteasyredirect extends Module
                                         INSERT INTO `'._DB_PREFIX_.'pagenotfound` (`request_uri`, `http_referer`, `date_add`, `id_shop`, `id_shop_group`)
-                    VALUES (\''.htmlentities($request_uri).'\', \''.htmlentities($http_referer).'\', NOW(), '.(int)$this->context->shop->id.', '.(int)$this->context->shop->id_shop_group.')
+                    VALUES (\''.pSQL(htmlentities($request_uri)).'\', \''.pSQL(htmlentities($http_referer)).'\', NOW(), '.(int)$this->context->shop->id.', '.(int)$this->context->shop->id_shop_group.')
                 '
@@ -446,3 +446,3 @@ class Oparteasyredirect extends Module
                                         INSERT INTO `'._DB_PREFIX_.'pagenotfound` (`request_uri`, `http_referer`, `date_add`, `id_shop`, `id_shop_group`)
-                    VALUES (\''.htmlentities($request_uri).'\', \''.htmlentities($http_referer).'\', NOW(), '.(int)$this->context->shop->id.', '.(int)$this->context->shop->id_shop_group.')
+                    VALUES (\''.pSQL(htmlentities($request_uri)).'\', \''.pSQL(htmlentities($http_referer)).'\', NOW(), '.(int)$this->context->shop->id.', '.(int)$this->context->shop->id_shop_group.')
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **oparteasyredirect**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-07-20 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-07-20 | Contact Author to confirm version scope |
| 2023-07-20 | Author confirm version scope |
| 2023-12-15 | Received CVE ID |
| 2024-02-08 | Publish this security advisory |

Opart thanks [TouchWeb](https://www.touchweb.fr) for its courtesy and its help after the vulnerability disclosure.

## Links

* [Author product page](https://www.store-opart.fr/p/20-sauvegarde-partage-lien-panier.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-50061)
