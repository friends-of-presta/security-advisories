---
layout: post
title: "[CVE-2023-46347] Improper neutralization of SQL parameter in NDK Design - Step by Step products Pack module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ndk_steppingpack"
severity: "critical (9.8)"
---

In the module "Step by Step products Pack" (ndk_steppingpack) up to 1.5.6 from NDK Design for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-46347](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46347)
* **Published at**: 2023-10-24
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: ndk_steppingpack
* **Impacted release**: <= 1.5.6 (1.5.7 fixed the vulnerability)
* **Product author**: NdkDesign
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `NdkSpack::getPacks()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

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
curl -v -d 'search_query=1%22%29;select+0x73656C65637420736C656570283432293B+into+@a;prepare+b+from+@a;execute+b;--' 'https://preprod.XX/modules/ndk_steppingpack/search-result.php'
```

## Patch from 1.5.6

```diff
--- 1.5.6/modules/ndk_steppingpack/models/ndkSpack.php
+++ 1.5.7/modules/ndk_steppingpack/models/ndkSpack.php
...
		if(isset($query) && $query !='')
		{
-			$where_product .= ' AND (cpl.name LIKE "%'.$query.'%" OR cpl.description LIKE "%'.$query.'%" OR cpl.short_description LIKE "%'.$query.'%")';
+			$where_product .= ' AND (cpl.name LIKE "%'.pSQL($query).'%" OR cpl.description LIKE "%'.pSQL($query).'%" OR cpl.short_description LIKE "%'.pSQL($query).'%")';
		}
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **ndk_steppingpack**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-05-25 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-25 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-05-25 | PrestaShop Addons security Team confirm versions scope by author |
| 2023-05-25 | Author provide a patch |
| 2023-05-26 | TouchWeb discover a critical issue - recontact PrestaShop Addons |
| 2023-10-16 | Author provide a patch |
| 2023-10-17 | Request a CVE ID |
| 2023-10-23 | Received CVE ID |
| 2023-10-24 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/ventes-croisees-packs-produits/20221-packs-produits-par-etapes.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-46347)
