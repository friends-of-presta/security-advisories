---
layout: post
title: "[CVE-2023-43984] Exposure of Private Personal Information to an Unauthorized Actor in Smart Soft - Advanced Export Products Orders Cron CSV Excel module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,advancedexport"
severity: "medium (7.5), GDPR violation"
---

In the module "Advanced Export Products Orders Cron CSV Excel" (advancedexport) in versions up to 4.4.6 from Smart Soft for PrestaShop, a guest can download personal information without restriction.

## Summary

* **CVE ID**: [CVE-2023-43984](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43984)
* **Published at**: 2023-11-07
* **Platform**: PrestaShop
* **Product**: advancedexport
* **Impacted release**: <= 4.4.6 (4.4.7 fixed the vulnerability)
* **Product author**: Smart Soft
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
* **Severity**: medium (7.5), GDPR violation

## Description

Due to a lack of permissions control and predictable (or easily brute-forcable) filename, a guest can access exports from the module which can lead to leak of personal information from ps_customer table such as name / surname / email / postal address / phone number.


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

## Timeline

| Date | Action |
|--|--|
| 2023-08-01 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-08-01 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-08-01 | PrestaShop Addons security Team confirms version scope |
| 2023-09-07 | Request a CVE ID |
| 2023-09-27 | Received CVE ID |
| 2023-11-07 | Publish this security advisory |

## Other recommendations

* You should restrict access to this URI pattern : modules/advancedexport/csv/ to a given whitelist
* You should restrict access to .csv file to a given whitelist

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/data-import-export/6927-advanced-export-products-orders-cron-csv-excel.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-43984)
