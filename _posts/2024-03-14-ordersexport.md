---
layout: post
title: "[CVE-2024-28396] Exposure of Sensitive Information to an Unauthorized Actor in MyPrestaModules - Orders (CSV, Excel) Export PRO module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,ordersexport"
severity: "medium (7.5), GDPR violation"
---

In the module "Orders (CSV, Excel) Export PRO" (ordersexport) up to version 6.0.2 from MyPrestaModules for PrestaShop, a guest can download sensitive information without restriction.

## Summary

* **CVE ID**: [CVE-2024-28396](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28396)
* **Published at**: 2024-03-14
* **Platform**: PrestaShop
* **Product**: ordersexport
* **Impacted release**: <= 6.0.2 (6.0.3 fixed the vulnerability)
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
* **Severity**: medium (7.5), GDPR violation

## Description

Due to a unprotected txt file and an unprotected download.php script, a guest can access sensitive information such as FTP credentials.


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

* Data leaks

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **ordersexport**.
* You should restrict access to the folder modules/ordersexport/ to a given whitelist

## Timeline

| Date | Action |
|--|--|
| 2023-10-19 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-10-19 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-10-19 | PrestaShop Addons security Team confirms version scope by author |
| 2024-02-07 | Author provide a patch |
| 2024-03-11 | Received CVE ID |
| 2024-03-14 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/data-import-export/17596-orders-csv-excel-export-pro.html)
* [Auhtor product page](https://myprestamodules.com/data-import-export/orders-csv-excel-import.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-28396)
