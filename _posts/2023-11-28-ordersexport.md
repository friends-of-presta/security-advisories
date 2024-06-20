---
layout: post
title: "[CVE-2023-46354] Exposure of Private Personal Information to an Unauthorized Actor in MyPrestaModules - Orders (CSV, Excel) Export PRO module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ordersexport"
severity: "high (7.5), GDPR violation"
---

In the module "Orders (CSV, Excel) Export PRO" (ordersexport) up to version 5.1.6 from MyPrestaModules for PrestaShop, a guest can download personal information without restriction.

## Summary

* **CVE ID**: [CVE-2023-46354](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46354)
* **Published at**: 2023-11-28
* **Platform**: PrestaShop
* **Product**: ordersexport
* **Impacted release**: <= 5.1.6 (5.2.0 fixed the vulnerability - See note below)
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
* **Severity**: high (7.5), GDPR violation

## Description

Due to a lack of permissions control, a guest can access exports from the module which can lead to leak of personal information from the ps_customer/ps_address tables such as firstname / lastname / email / phone number / full postal address

Note : The vulnerability has been seen in a 4.7.1 version and the implicated file has been deleted on version 5.2.0, so we consider all versions up to 5.1.6 as impacted.

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

* Steal personal data

## Other recommendations

* You should restrict access to this URI pattern : modules/ordersexport/ to a given whitelist

## Timeline

| Date | Action |
|--|--|
| 2023-05-28 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-28 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-09-27 | PrestaShop Addons security Team confirms versions scope by author |
| 2023-10-17 | Request a CVE ID |
| 2023-10-23 | Received CVE ID |
| 2023-11-28 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/data-import-export/17596-orders-csv-excel-export-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-46354)
