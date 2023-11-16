---
layout: post
title: "[CVE-2023-45380] Exposure of Private Personal Information to an Unauthorized Actor in Silbersaiten - Order Duplicator – Clone and Delete Existing Order module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,orderduplicate"
severity: "medium (7.5), GDPR violation"
---

In the module "Order Duplicator – Clone and Delete Existing Order" (orderduplicate) in versions up to 1.1.7 from Silbersaiten for PrestaShop, a guest can download personal information without restriction.

## Summary

* **CVE ID**: [CVE-2023-45380](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45380)
* **Published at**: 2023-11-07
* **Platform**: PrestaShop
* **Product**: orderduplicate
* **Impacted release**: <= 1.1.7 (1.1.8 fixed the vulnerability)
* **Product author**: Silbersaiten
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html) [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
* **Severity**: medium (7.5), GDPR violation

## Description

Due to a lack of permissions control, a guest can download personal information from ps_customer/ps_address tables such as name / surname / phone number / full postal address.

Be warned that this is not the only IDOR available in this module, patch it quickly.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: low
* **Availability**: low

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

## Possible malicious usage

* Steal personal data
* Delete data

## Other recommendations

* You should restrict access to this URI pattern : modules/orderduplicate/ to a given whitelist

## Timeline

| Date | Action |
|--|--|
| 2023-07-03 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-07-03 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-07-11 | PrestaShop Addons security Team confirms versions scope |
| 2023-10-08 | Request a CVE ID |
| 2023-10-11 | Received CVE ID |
| 2023-11-07 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/registration-ordering-process/19043-order-duplicator-clone-and-delete-existing-order.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45380)
