---
layout: post
title: "[CVE-2022-40839] Improper neutralization of SQL parameter in NdkAdvancedCustomizationFields module for PrestaShop"
categories: module
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ndkadvancedcustomizationfields"
severity: "high (7.5)"
---

A SQL injection vulnerability in the height and width parameter in NdkAdvancedCustomizationFields v3.5.0 allows unauthenticated attackers to exfiltrate database data.

## Summary

* **CVE ID**: [CVE-2022-40839](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40839)
* **Published at**: 2022-11-01
* **Advisory source**: [github](https://github.com/daaaalllii/cve-s/blob/main/CVE-2022-40839/poc.txt)
* **Vendor**: PrestaShop
* **Product**: NdkAdvancedCustomizationFields
* **Impacted release**: <= 3.5.0
* **Product author**: 
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5)

## Description

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: none
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch

Prestashop provide a built in function for sanitising strings to be used in SQL queries called pSQL. This is the quick fix in situations like this but one must be sure to surround the parameter with quotes or the query will still be vulnerable to SQLi

For the function getDimensionPrice, the two problematics parameters, width and height were put in pSQL functions to be sanitised as shown :

```diff
--- a/models/ndkCf.php
+++ b/models/ndkCf.php
@@ -698,589 +1369,1100 @@ class NdkCf extends ObjectModel

	public static function getDimensionPrice($field, $width, $height)
	{
-		$field = new NdkCf((int)$field);
-		if($field->type == 21 || $field->type == 19){
+		$field = new NdkCf((int) $field);
+		if (21 == $field->type || 19 == $field->type) {
 			//on cherche la valeur exacte
 			$result = Db::getInstance(_PS_USE_SQL_SLAVE_)->getRow(
-				'SELECT price FROM '._DB_PREFIX_.'ndk_customization_field_csv
-						WHERE id_ndk_customization_field = '.(int)$field->id.'
-						AND width = \''.$width.'\' AND height = \''.$height.'\'');
+				'SELECT price FROM '.
+					_DB_PREFIX_.
+					'ndk_customization_field_csv
+						WHERE id_ndk_customization_field = '.
+					(int) $field->id.
+					'
+						AND width = \''.
+					pSQL($width).
+					'\' AND height = \''.
+					pSQL($height).
+					'\''
+			);
 			//var_dump($result);
 			$item_price = str_replace(',', '.', $result['price']);
+
 			return $item_price;
-		}
-		else
-		{
-			$sql = 'SELECT price FROM '._DB_PREFIX_.'ndk_customization_field_csv
-					WHERE id_ndk_customization_field = '.(int)$field->id.'
-					ORDER BY ABS(width-'.$width.') ASC, ABS(height-'.$height.') ASC LIMIT 1';
+		} else {
+			// $sql = 'SELECT price FROM '._DB_PREFIX_.'ndk_customization_field_csv
+			// 		WHERE id_ndk_customization_field = '.(int)$field->id.'
+			// 		ORDER BY ABS(width-'.$width.') ASC, ABS(height-'.$height.') ASC LIMIT 1';
+			$sql =
+				'SELECT price FROM '.
+				_DB_PREFIX_.
+				'ndk_customization_field_csv
+			WHERE id_ndk_customization_field = '.
+				(int) $field->id.
+				'
+			AND width >= '.
+				(float)$width.
+				' AND height >= '.
+				(float)$height.
+				' 
+			LIMIT 1';
 			$result = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS($sql);
-			if($result)
-			{
+			if ($result) {
 				$item_price = str_replace(',', '.', $result[0]['price']);
+
 				return $item_price;
 			}
 		}
 	}
```

But the function getRangePrice is still the same :

```diff
--- a/models/ndkCf.php
+++ b/models/ndkCf.php
@@ -698,589 +1369,1100 @@ class NdkCf extends ObjectModel

 	public static function getRangePrice($field, $width, $height)
 	{
 		$results = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS(
-			'SELECT * FROM '._DB_PREFIX_.'ndk_customization_field_csv
-				WHERE id_ndk_customization_field = '.(int)$field->id.'
-				AND width >= '.$width.' AND height >= '.$height.'
-				ORDER BY width ASC');
+            'SELECT * FROM '.
+                _DB_PREFIX_.
+                'ndk_customization_field_csv
+				WHERE id_ndk_customization_field = '.
+                (int) $field->id.
+                '
+				AND width >= '.
+                $width.
+                ' AND height >= '.
+                $height.
+                '
+				ORDER BY width ASC'
+        );
 
-		if($results)
-		{
+        if ($results) {
 			//var_dump($results[0]);
 			$item_price = str_replace(',', '.', $results[0]['price']);
+
 			return $item_price;
 		}
-
-
 	}
```


## Other recommendations

* Upgrade the module to the most recent version
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 01-11-2022 | GitHub Poc |

## Links

* [Source of this CVE](https://github.com/daaaalllii/cve-s/blob/main/CVE-2022-40839/poc.txt)
* [National Vulnerability Database CVE-2022-40839](https://nvd.nist.gov/vuln/detail/CVE-2022-40839)