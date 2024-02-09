---
layout: post
title: "[CVE-2023-50026] Improper neutralization of SQL parameter in Presta Monster - Multi Accessories Pro module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- Ambris Informatique
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,hsmultiaccessoriespro"
severity: "critical (9.8)"
---

In the module "Multi Accessories Pro" (hsmultiaccessoriespro) up to version 5.2.0 from Presta Monster for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-50026](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50026)
* **Published at**: 2024-02-08
* **Platform**: PrestaShop
* **Product**: hsmultiaccessoriespro
* **Impacted release**: <= 5.2.0 (5.3.0 fixed the vulnerability)
* **Product author**: Presta Monster
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method HsAccessoriesGroupProductAbstract::getAccessoriesByIdProducts() has a sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

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


## Patch from 5.2.0

```diff
--- 5.2.0/modules/hsmultiaccessoriespro/abstract/classes/HsAccessoriesGroupProductAbstract.php
+++ 5.3.0/modules/hsmultiaccessoriespro/abstract/classes/HsAccessoriesGroupProductAbstract.php
...
            $query->from('accessory_group_product', 'agp');
-           $query->where('agp.`id_product` IN (' . implode(',', $id_products) . ')');
+           $query->where('agp.`id_product` IN (' . implode(',', array_map('intval', $id_products)) . ')');
            $query->where('ag.`active` = 1');
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **hsmultiaccessoriespro**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-08-10 | Issue discovered during a code review by [Ambris Informatique](https://ambris.com/) and [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-08-10 | Contact PrestaShop Addons security Team to confirm version scope |
| 2023-08-18 | PrestaShop Addons security Team confirms version scope |
| 2023-12-12 | Received CVE ID |
| 2024-02-08 | Publish this security advisory |

## Links

* [Author product page](https://addons.prestashop.com/fr/ventes-croisees-packs-produits/23426-multi-accessories-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-50026)
