---
layout: post
title: "[CVE-2023-27639][CVE-2023-27640][CWE-22] Multiple path traversal in Custom Product Designer (tshirtecommerce) module for PrestaShop"
categories: module
author:
- Profileo
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,tshirtecommerce"
severity: "critical (9.8)"
---

In the Custom Product Designer (tshirtecommerce) module for PrestaShop, HTTP requests can be forged using POST and GET parameters enabling a remote attacker to perform directory traversal on the system and view the contents of code files. Since the module appears not to have been maintained since 2019, it is strongly recommended to remove it.

## Summary

* **CVE ID**: [CVE-2023-27639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27639) / [CVE-2023-27640](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27640)
* **Published at**: 2023-03-30
* **Advisory source**: Friends-Of-Presta
* **Vendor**: PrestaShop
* **Product**: tshirtecommerce
* **Impacted release**: <= 2.1.4 (latest version)
* **Product author**: Tshirtecommerce Team
* **Weakness**: [CWE-22](https://www.cvedetails.com/cwe-details/22/cwe.html)
* **Severity**: critical (9.8)

## Description

The following issues have been seen in the latest version of the Prestashop Custom Product Designer (tshirtecommerce) module for PrestaShop, released on July 24, 2019 (not fixed up to date) :
- an HTTP request can be manipulated using the GET parameter `type` in the `/tshirtecommerce/fonts.php` endpoint, enabling a remote attacker to perform directory traversal on the system and open files without restrictions on the extension and path. The content of the file will be returned in base64-encoded format.
- an HTTP request can be manipulated using the POST parameter `file_name` in the `tshirtecommerce/ajax.php?type=svg` endpoint, enabling a remote attacker to perform directory traversal on the system and open files without restrictions on the extension and path. Note that only files that can be parsed in XML format can be opened.

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

* Obtain database access
* Extract sensitive data, such as tokens or private keys stored in config files
* Extract other private data, such as log files or exports

## Proof of concept

Examples:

1. For all types of files, will return a base64 response of the content of the file (critical):
```bash
https://example.test/tshirtecommerce/fonts.php?name=2&type=./../index.php
```

2. When a file can be parsed as XML without error (less common):
```bash
curl --request POST 'https://example.test/tshirtecommerce/ajax.php?type=svg' \
--data-urlencode 'url=./../vendor/jdorn/sql-formatter/examples' \
--data-urlencode 'file_name=examples.php'
```

## Patch 

```diff
--- a/tshirtecommerce/fonts.php        
+++ b/tshirtecommerce/fonts.php        
@@ -85,6 +85,24 @@ if (isset($_GET['name']) && isset($_GET['type']))
                else
                {
                        $file_font = ROOT .DS. $font_type;
+            
+            // Array of allowed font file extensions
+            $allowed_extensions = array('ttf', 'otf', 'woff', 'woff2', 'eot', 'svg');
+            // Get the file extension of the file_font
+            $file_extension = strtolower(pathinfo($file_font, PATHINFO_EXTENSION));
+            // Check if the file extension is one of the allowed font types
+            if (!in_array($file_extension, $allowed_extensions)) {
+                exit();
+            } 
+            // tshirtecommerce base path
+            $tshirtecommerceBase = realpath(dirname(__FILE__));
+            // requested file path
+            $fileRealPath = realpath($file_font);
+            if ($fileRealPath === false || strpos($fileRealPath, $tshirtecommerceBase) !== 0) {
+                // Directory transversal
+                exit();
+            }
+
```

In the function `getSVG`.
```diff
--- a/tshirtecommerce/includes/functions.php   
+++ b/tshirtecommerce/includes/functions.php   
@@ -1480,6 +1480,22 @@ class dg{
                        $file           = $url . 'print/' . $file_name;
                else
                        $file           = $url . '/' . $file_name;
+        
+        // tshirtecommerce base path
+        $tshirtecommerceBase = realpath(dirname(__FILE__)."/../");
+        // requested file path
+        $fileRealPath = realpath($file);
+        if ($fileRealPath === false || strpos($fileRealPath, $tshirtecommerceBase) !== 0) {
+            // Directory transversal
+            exit();
+        }
+
+        // Check if extension if SVG
+        // Warning : This code might break things if tshirtecommerce is waiting for other file extensions
+        $pathinfo = pathinfo($file);
+        if ($pathinfo['extension'] != 'svg') {
+            exit();
+        }

```

## Timeline

If the CVE is published by Friends of Presta.

| Date | Action |
| -- | -- |
| 2022-10-23 | First detection in Apache logs of an exploitation of this module |
| 2023-03-04 | Discovery of the vulnerability by Profileo |
| 2023-03-04 | Contacting the editor (no reply) |
| 2023-03-04 | Contacting codecanyon / envato market |
| 2023-03-07 | Email reminder to the editor (no reply) |
| 2023-03-07 | Email reminder to the editor by another channel (no reply) |
| 2023-03-09 | Email reminder to the editor (no reply) |
| 2023-03-16 | Contacting again codecanyon / envato market |
| 2023-03-21 | Publish this security advisory |

## Links

* [Module Custom Product Designer (tshirtecommerce)](https://codecanyon.net/item/prestashop-custom-product-designer/19202018)
* [Editor Website : T-Shirt eCommerce](https://tshirtecommerce.com/)
* [National Vulnerability Database CVE-2023-27639](https://nvd.nist.gov/vuln/detail/CVE-2023-27639)
* [National Vulnerability Database CVE-2023-27640](https://nvd.nist.gov/vuln/detail/CVE-2023-27640)
