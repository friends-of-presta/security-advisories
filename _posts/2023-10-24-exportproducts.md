---
layout: post
title: "[CVE-2023-46346] Improper Limitation of a Pathname to a Restricted Directory in MyPrestaModules - Product Catalog (CSV, Excel, XML) Export PRO module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,exportproducts"
severity: "high (7.5), GDPR violation"
---

In the module "Product Catalog (CSV, Excel, XML) Export PRO" (exportproducts) up to 4.1.1 from MyPrestaModules for PrestaShop,, a guest can download personal informations without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2023-46346](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46346)
* **Published at**: 2023-10-24
* **Platform**: PrestaShop
* **Product**: exportproducts
* **Impacted release**: <= 4.1.1 (5.0.0 fixed the vulnerability)
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5)

## Description

Due to a lack of permissions control and a lack of control in the path name construction, a guest can perform a path traversal to view all files on the information system.

Note : We are forced to tag it as a high gravity due to the CWE type 22 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds admin's ajax script of modules due to [this](https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247)

**WARNING** : Be informed that this vulnerability is exploited since October 16, 2023.

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

* Stealing secrets to unlock admin controllers based on ajax script
* Exfiltrate all modules with all versions to facilitate pentesting
* Stealing table_prefix to greatly facilitate SQL injections for kiddies who don't know how to exploit DBMS design's vulnerabilities or steal database access to login in exposed PHPMyAdmin/Adminer/etc.
* Bypass WAF / htaccess restrictions to read forbidden files (such as logs on predictable paths of banks's modules inside /var/log/)

## Proof of concept

```bash
curl -v -d 'url=../../config/settings.inc.php' 'https://preprod.XX/modules/exportproducts/download.php'
```

## Patch from 4.1.1

The file has been comptely rewritten on 5.0.0.

```diff
--- 4.1.1/modules/exportproducts/functions/download.php
+++ XXXXX/modules/exportproducts/functions/download.php
...
-$file = Tools::getValue('url');
+$file = basename(Tools::getValue('url'));
$file_info  = pathinfo($file);

```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **exportproducts**.
* You should consider restricting the access of modules/exportproducts/ to a whitelist
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop

## Timeline

| Date | Action |
|--|--|
| 2023-10-16 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-10-16 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-10-16 | PrestaShop Addons confirms versions scopes |
| 2023-10-16 | Request a CVE ID |
| 2023-10-23 | Received CVE ID |
| 2023-10-24 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/data-import-export/18662-product-catalog-csv-excel-xml-export-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-46346)
