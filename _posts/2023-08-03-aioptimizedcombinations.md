---
layout: post
title: "[CVE-2023-33666] Improper neutralization of a SQL parameter in aioptimizedcombinations from ai-dev module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,aioptimizedcombinations"
severity: "critical (9.8)"
---

In the module "Customization fields fee for your store" (aioptimizedcombinations) for PrestaShop, an attacker can perform a SQL injection up to 0.1.2. Release 0.1.3 fixed this security issue.

## Summary

* **CVE ID**: [CVE-2023-33666](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33666)
* **Published at**: 2023-08-03
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: aioptimizedcombinations
* **Impacted release**: <= 0.1.2 (0.1.3 fixed issue)
* **Product author**: ai-dev
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Up to 0.1.3, a sensitive SQL call in file `includes/ajax.php` can be executed with a trivial http call and exploited to forge a blind SQL injection throught the POST or GET submitted `attributes` variables.

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

## Patch

```diff
--- a/modules/aioptimizedcombinations/includes/ajax.php
+++ b/modules/aioptimizedcombinations/includes/ajax.php
switch (Tools::getValue('action'))
{
	case 'getCombination' :
		/* If no product or combination, we quit */
		if (!Tools::getIsset('product') || !Tools::getIsset('attributes'))
			die();

		$attributes = explode(',', Tools::getValue('attributes'));
		
		/* Get combination id */
		$combination_data = Db::getInstance()->getRow(
			'SELECT COUNT(*) as number, pa.id_product_attribute FROM '._DB_PREFIX_.'product_attribute AS pa LEFT JOIN '._DB_PREFIX_.'product_attribute_combination AS pac ON pa.id_product_attribute = pac.id_product_attribute WHERE pa.id_product = '.
-			(int)Tools::getValue('product').' AND pac.id_attribute IN ('.pSQL(Tools::getValue('attributes')).') GROUP BY pa.id_product_attribute HAVING number = '.count($attributes)
+			(int)Tools::getValue('product').' AND pac.id_attribute IN ('.implode(',', array_map('intval', explode(',', Tools::getValue('attributes')))).') GROUP BY pa.id_product_attribute HAVING number = '.count($attributes)
		);
```


## Other recommandations

* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-05-08 | Vunlnerability found during a audit by [202 ecommerce](https://www.202-ecommerce.com/) |
| 2023-05-10 | Contact the author |
| 2023-05-12 | The author confirm the issue and supply a fixed release |
| 2023-05-12 | Request a CVE ID |
| 2023-08-03 | Publication of this advisory |


## Links

* [Author product page](https://www.boutique.ai-dev.fr/en/ergonomie/59-optimized-combinations.html)
* [National Vulnerability Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33666)

