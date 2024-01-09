---
layout: post
title: "[CVE-2023-48926] Insecure Direct Object Reference in Advanced Loyalty Program: Loyalty Points module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,totloyaltyadvanced"
severity: "critical (7.5)"
---

In the module "Advanced Loyalty Program: Loyalty Points" (totloyaltyadvanced) from 2.3.3 to version 2.3.4 from 202 ecommerce for PrestaShop, a guest can change an order status.

## Summary

* **CVE ID**: [CVE-2023-48926](https://github.com/202ecommerce/security-advisories/security/advisories/GHSA-jp2c-mj65-qpmw)
* **Published at**: 2024-01-09
* **Platform**: PrestaShop
* **Product**:  totloyaltyadvanced
* **Advisory source**: [202 ecommerce](https://github.com/202ecommerce/security-advisories/security/advisories/GHSA-jp2c-mj65-qpmw)
* **Impacted release**: >= 2.3.3, < 2.3.4 (2.3.4 fix the issue)
* **Product author**: 202 ecommerce
* **Weakness**: [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
* **Severity**: critical (7.5)

## Description

The orderstatus front controller suffers from a logical weakness.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: none
* **Integrity**: high
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)

## Possible malicious usage

* Confirm an unpaid cart


## Patch

Remove file `controllers/front/orderstatus.php`


## Timeline

| Date | Action |
|--|--|
| 2023-10-22 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-10-22 | Contact Author to confirm version scope by author |
| 2023-11-09 | Publish a new release on addons |
| 2023-11-15 | Request a CVE ID |
| 2024-01-09 | Publish this advisory |

## Links

* [Advisory source](https://github.com/202ecommerce/security-advisories/security/advisories/GHSA-jp2c-mj65-qpmw)
* [PrestaShop addons product page](https://addons.prestashop.com/en/referral-loyalty-programs/7301-advanced-loyalty-program-loyalty-points.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-48926)
