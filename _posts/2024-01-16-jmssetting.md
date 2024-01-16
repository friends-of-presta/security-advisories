---
layout: post
title: "[CVE-2023-50030] Blind SQL injection vulnerability in Joommasters - Jms Setting module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Creabilis.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
severity: "critical (9.8)"
---


In the module "Jms Setting" (jmssetting) from Joommasters for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-50030](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50030)
* **Published at**: 2024-01-16
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: jmssetting
* **Impacted release**: at least <= 1.1.0
* **Product author**: Joommasters
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `JmsSetting::getSecondImgs()` has a sensitive SQL call that can be executed with a trivial http call and exploited to forge a blind SQL injection.

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

* Technical and personal data leaks
* Obtain admin access
* Remove all data of the linked PrestaShop
* Display sensitives tables to front-office to unlock potential admin's ajax scripts of modules protected by token on the ecosystem

## Proof of concept

```bash
curl -v "https://preprod.x/modules/jmssetting/initajax.php?productids[1]=1);select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--"
```

## Patch

```diff
--- 1.1.0/modules/jmssetting/jmssetting.php
+++ XXXXX/modules/jmssetting/jmssetting.php
...
	public function getSecondImgs($productids)
	{
		$link = $this->context->link;
		$id_lang = Context::getContext()->language->id;
-		$where  = ' WHERE i.`id_product` IN ('.$productids.') AND i.`cover`=0';
+		$where  = ' WHERE i.`id_product` IN ('.implode(',', array_map('intval', explode(',', $productids.'))) AND i.`cover`=0';
...
```

## Timeline

| Date | Action |
|--|--|
| 2023-10-23 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-10-23 | Contact the author |
| 2023-11-29 | Request a CVE ID |
| 2023-12-12 | Received CVE ID |
| 2024-01-16 | Publish this security advisory |

## Other recommendations

* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [Joom masters web site](https://www.joommasters.com/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-50030)
