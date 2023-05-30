---
layout: post
title: "[CVE-2023-30192] Improper neutralization of SQL parameter in PosThemes - Search Products for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,possearchproducts"
severity: "critical (9.8)"
---

In the module "Search Products" (possearchproducts) from PosThemes for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-30192](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30192)
* **Published at**: 2023-05-11
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: possearchproducts
* **Impacted release**: <= 1.7 (VERSION'S SCOPE NOT CONFIRMED - AUTHOR NEVER ANSWER)
* **Product author**: posthemes
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `PosSearch::find()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

The exploit can be used even if the module is not activated.

**WARNING** : This exploit is actively used to deploy webskimmer to massively stole credit cards.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data on the associated PrestaShop
* Copy/past datas from sensibles tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijacked emails


## Proof of concept


```bash
curl -v 'https://preprod.XXX/modules/possearchproducts/SearchProducts.php?s=test&id_category=1;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--'
```

## Patch from 1.7

```diff
--- 1.7/modules/possearchproducts/PosSearch.php
+++ XXX/modules/possearchproducts/PosSearch.php
...
WHERE c.`active` = 1
-        '.($id_category !=  0 ? 'AND c.`id_category` = '.$id_category.'':'').'
+        '.($id_category !=  0 ? 'AND c.`id_category` = '.(int) $id_category.'':'').'
```

## Other recommandations

* It’s recommended to apply patch given or delete the module (NB : disabled it is useless)
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-03-23 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-03-23 | Contact Author to confirm versions scope |
| 2023-05-11 | Author never answer and exploit is used to massively stole credit cards |
| 2023-05-11 | Publication of this security advisory without delay due to emergency |


## Links

* [Posthemes product page on Themes Forest](https://themeforest.net/user/posthemes/portfolio)
* [Posthemes website](https://posthemes.com/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-30192)

