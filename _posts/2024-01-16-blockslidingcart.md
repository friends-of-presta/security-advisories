---
layout: post
title: "[CVE-2023-50028] Improper neutralization of SQL parameter in PrestashopModules.eu - Sliding cart block for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Wepika - Antoine
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,blockslidingcart"
severity: "critical (9.8)"
---

In the module "Sliding cart block" (blockslidingcart) up to version 2.3.8 from PrestashopModules.eu for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-50028](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50028)
* **Published at**: 2024-01-16
* **Platform**: PrestaShop
* **Product**: blockslidingcart
* **Impacted release**: <= 2.3.8 (all versions)
* **Product author**: PrestashopModules.eu
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `Blockslidingcart::renderModal()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

Warning : author discontinue support - you must avoid to use it.

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



## Patch from 2.3.8

```diff
--- 2.3.8/modules/blockslidingcart/blockslidingcart.php
+++ XXXXX/modules/blockslidingcart/blockslidingcart.php
...
        }
-       $crossproductIds = array($id_product);
+       $crossproductIds = array_map('intval', explode(',', $id_product));
        $q_orders = 'SELECT o.id_order
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **blockslidingcart**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-01-02 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-10-18 | Wepika - Antoine found it too and remain us to do the CVE |
| 2023-10-18 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-11-29 | Request a CVE ID |
| 2023-12-04 | PrestaShop Addons security Team confirms version scope |
| 2023-12-12 | Received CVE ID |
| 2024-01-16 | Publish this security advisory |

## Links

* [Author product page](https://prestashopmodules.eu/)
* [PrestaShop addons product page](https://addons.prestashop.com/en/express-checkout-process/3321-block-sliding-cart.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-50028)
