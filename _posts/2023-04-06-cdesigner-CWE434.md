---
layout: post
title: "[CVE-2023-27033] Unrestricted Upload of File with Dangerous Type in Cdesigner module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,cdesigner"
severity: "critical (9.8)"
---

In the module "Cdesigner" (cdesigner) up to 3.2.1 (3.2.2 fix the issue), a guest can upload files with extensions \.php.+ (like .php7)

Note : .php extension is correctly block so it will be harmless for most servers's setups.

## Summary

* **CVE ID**: [CVE-2023-27033](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27033)
* **Published at**: 2023-04-06
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: cdesigner
* **Impacted release**: > 3.1.3, <= 3.2.1 (3.2.2 fix the issue)
* **Product author**: Prestaeg
* **Weakness**: [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
* **Severity**: critical (9.8)

## Description

Important : If you use default configuration for your server, *you should be safe* - which should be the case of the majority of servers, so don't worry too much about this CVE. 

*We are forced to tag it as critical since it will be critical for some setups, but for the majority, it should be completly harmless.*

You can check if you are vulnerable by uploading files with extensions : .php3 / .php4 / .php5 / .php7 / .php8 with this content : <?php echo (21+21); - when you make a HTTP call against theses files, if you do not see 42, all is OK else, you service is vulnerable, contact without delay your hoster.

The method `CdesignerSaverotateModuleFrontController::initContent()` misuses strpos which can lead to upload .phpX files, depending on your server's setup, which will lead to a critical vulnerability [CWE-94](https://cwe.mitre.org/data/definitions/94.html).

**This exploit is actively exploited in the wild**

**WARNING** : If your service is vulnerable, be warn that this exploit will bypass some WAF (base64 payloads)


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
* Remove data on the associated PrestaShop
* Steal datas

## Patch

```diff
--- 3.1.8/cdesigner/controllers/front/saverotate.php
+++ 3.2.2/cdesigner/controllers/front/saverotate.php

+		$allowed = array('jpg', 'jpeg', 'png');
 		$found = false;
 		$not_allowed =array('.zip','.rar','.html','.tar','.php','.exe','.js','.py','.jsp','.asp','.txt', '.pht','.phtml', '.shtml', '.asa', '.cer', '.asax', '.swf', '.xap');
...
-		if ($img != '')
+		if ($img != '' && in_array( $ext, $allowed ))
 		{
 			$decoded = base64_decode(str_replace('data:image/'.$ext.';base64,', '', $img));
 			file_put_contents(dirname(__FILE__).'/../../views/img/upload/_'.$dates.'.'.$ext, $decoded);
+		} else {
+			echo 'Suspect Operation !!!';
+			exit();
 		}
```

## Other recommandations

* It’s recommended to apply patch without delay if your setup is vulnerable
* You must not allowed PHP Interpreter on anything than files with an extension strictly equal to ".php".

## Timeline

| Date | Action |
|--|--|
| 2023-02-19 | Issue discovered after a security audit by [TouchWeb](https://www.touchweb.fr) |
| 2023-02-19 | Contact PrestaShop Addons security Team |
| 2023-02-19 | Request CVE ID |
| 2023-02-27 | Addons security Team confirm author provide a patch for PS 1.6 and PS 1.7/8.0 |
| 2023-04-06 | Publication of the security advisory without delay : exploit is actively used |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/declinaisons-personnalisation/22677-personnalisation-de-produit-product-customize.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-27033)

