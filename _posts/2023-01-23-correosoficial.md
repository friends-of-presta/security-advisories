---
layout: post
title: "[CVE-2022-46639] Directory traversal in the descarga_etiqueta.php component of Correos Prestashop"
categories: modules
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,correosoficial"
severity: "high (7.5)"
---

From version v1.1.0.0 and v1.2.x+ correosoficial Module for Prestashop 1.7.x allows remote attackers to read local files and attack intranet hosts.

## Summary

* **CVE ID**: [CVE-2022-46639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-46639)
* **Published at**: 2023-01-23
* **Advisory source**: [ia-informatica.com](https://ia-informatica.com/it/CVE-2022-46639)
* **Vendor**: PrestaShop
* **Product**: correosoficial
* **Impacted release**: >= 1.1.0, < 1.2.0
* **Product author**: Grupo Correos
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: high (7.5)

## Description

File: modules/correosoficial/descarga_etiqueta.php
Vulnerable Argument(s): $_REQUEST['filename'] and $_REQUEST['path']

modules/correosoficial/descarga_etiqueta.php in Correos-PrestaShop Module v1.2.0.0 for PrestaShop 1.7.x allows remote attackers to read local files, attack intranet hosts via "path" and "filename" parameters.

The descarga_etiqueta.php component of Correos use the PHP function `readfile`, without sanitize the parameters.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: low
* **Availability**: low

**Vector string**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Possible malicious usage

Remote users can read all files inside and outside the document root, credentials can be compromised
* Technical data leak like a database configuration, logs, ...
* Personnal data leak stored in files

## Proof of concept

```bash
curl -v 'http://domain.tld/modules/correosoficial/descarga_etiqueta.php?path=X&filename=X.'
```

## Patch

Validate all user input, block all paths outside the your PDF folder, add an authorization header.

An official patch is not yet published by the author of the module. Please note, this proposal to filter pdf to display and limit access to the pdftmp path.

```diff
--- a/descarga_etiqueta.php
+++ b/descarga_etiqueta.php
@@ -8,7 +8,12 @@
 header('Content-Type: application/pdf');
 
-$filename = $_REQUEST['filename'];
+$filename = basename($_REQUEST['filename']);
-$path = $_REQUEST['path'];
+$path = 'pdftmp';
+
+$pathinfo = pathinfo($path . "/" . $filename);
+if ($pathinfo['extension'] != 'pdf') {
+    exit;
+}
 
 // Se llamara downloaded.pdf y se descargará como adjunto
 header('Content-Disposition: attachment; filename="'.$filename.'"');

```

## Other recommandations

* At the date of the CVE publication, the module was not fixed !
* Remove this module if it is not useful.

## Links

* [ia-informatica.com security advisory post](https://ia-informatica.com/it/CVE-2022-46639)
* [Product page](https://www.correos.es/es/es/empresas/ecommerce/agiliza-la-gestion-de-tus-pedidos/prestashop)
* [National Vulnerability Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-46639)
