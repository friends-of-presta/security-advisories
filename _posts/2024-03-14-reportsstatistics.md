---
layout: post
title: "[CVE-2024-28394] External Control of File Name or Path in Advanced Plugins - Sales Reports, Statistics, Custom Fields & Export module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,reportsstatistics"
severity: "critical (9.1)"
---

In the module "Sales Reports, Statistics, Custom Fields & Export" (reportsstatistics) in versions up to 1.3.20 from Advanced Plugins for PrestaShop, a guest can download and delete all files.

## Summary

* **CVE ID**: [CVE-2024-28394](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28394)
* **Published at**: 2024-03-14
* **Platform**: PrestaShop
* **Product**: reportsstatistics
* **Impacted release**: <= 1.3.20 (1.3.30 fixed the critical issue - see WARNING below)
* **Product author**: Advanced Plugins
* **Weakness**: [CWE-73](https://cwe.mitre.org/data/definitions/73.html)
* **Severity**: critical (9.1)

## Description

Due to a broken access control, a guest can delete all files of the PrestaShop including .htaccess to access protected folders to steal sensitives data.

**WARNING** : Be warned that the module still has sensitive issues that suffer a CVSS score 3.1 <= 7.2/10.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: none
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)

## Possible malicious usage

* Download and delete all files from the Shop
* Disable critical security configuration (.htaccess)


## Patch from 1.3.20

```diff
--- 1.3.20/module/reportsstatistics/export/export.php
+++ XXXXXX/module/reportsstatistics/export/export.php
...
-$file = urldecode(Tools::getValue('file'));
+$file = basename(urldecode(Tools::getValue('file')));

if(file_exists(dirname(__FILE__).'/'.$file))
{
	header('Content-type: application/vnd.ms-excel');
	header('Content-Disposition: attachment; filename='.$file);
	readfile(dirname(__FILE__).'/'.$file);
	unlink(dirname(__FILE__).'/'.$file);
	die();
}
...
```


```diff
--- 1.3.12/module/reportsstatistics/ajax_public.php
+++ XXXXXX/module/reportsstatistics/ajax_public.php
...
-			$current_value = Tools::jsonDecode(unserialize($context->cookie->apc_fields), true);
+			$current_value = Tools::jsonDecode(unserialize($context->cookie->apc_fields, ['allowed_classes' => false]), true); // Harmless until proven otherwise just for the principle.
...
```

Seen by a contributor in 1.3.20 :

```diff
--- 1.3.20/module/reportsstatistics/reportsstatistics.php
+++ XXXXXX/module/reportsstatistics/reportsstatistics.php
@@ -643 +643 @@ class reportsstatistics extends Module
-            $current_value = Tools::jsonDecode(unserialize($context->cookie->apc_fields), true);
+            $current_value = Tools::jsonDecode(unserialize($context->cookie->apc_fields, ['allowed_classes' => false]), true); // Harmless until proven otherwise just for the principle.
@@ -670 +670 @@ class reportsstatistics extends Module
-            $current_value = Tools::jsonDecode(unserialize($context->cookie->apc_fields), true);
+            $current_value = Tools::jsonDecode(unserialize($context->cookie->apc_fields, ['allowed_classes' => false]), true); // Harmless until proven otherwise just for the principle.
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **reportsstatistics**.
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop

## Timeline

| Date | Action |
|--|--|
| 2023-09-22 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-09-22 | Contact PrestaShop Addons security Team to confirm version scope |
| 2023-09-27 | PrestaShop Addons security Team confirms version scope by author |
| 2024-01-25 | Author provided a patch for the critical issue but there are still high issues |
| 2024-03-11 | Received CVE ID |
| 2024-03-14 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/customer-administration/28379-sales-reports-statistics-custom-fields-export.html)
* [Author product page](https://advancedplugins.com/prestashop/modules/advanced-fields-statistics-customer-segmentation/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-28394)
