---
layout: post
title: "[CVE-2023-46352] Exposure of Private Personal Information to an Unauthorized Actor in Smart Modules - Pixel Plus: Events + CAPI + Pixel Catalog for Facebook Module module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,facebookconversiontrackingplus"
severity: "medium (7.5), GDPR violation"
---

In the module "Pixel Plus: Events + CAPI + Pixel Catalog for Facebook Module" (facebookconversiontrackingplus) up to version 2.4.8 from Smart Modules for PrestaShop, a guest can download personal informations without restriction.

## Summary

* **CVE ID**: [CVE-2023-46352](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46352)
* **Published at**: 2023-10-31
* **Platform**: PrestaShop
* **Product**: facebookconversiontrackingplus
* **Impacted release**: <= 2.4.8 (2.4.9 fixed the vulnerability)
* **Product author**: Smart Modules
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
* **Severity**: medium (7.5), GDPR violation

## Description

Due to a lack of permissions control, a guest can access exports from the module which can lead to leak of personal informations from ps_customer table such as name / surname / email


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
| 2023-05-24 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-24 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-10-10 | PrestaShop Addons security Team confirm versions scope by author |
| 2023-10-11 | Author provide patch |
| 2023-10-17 | Request a CVE ID |
| 2023-10-23 | Received CVE ID |
| 2023-10-31 | Publish this security advisory |

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **facebookconversiontrackingplus**.
* You should restrict access to this URI pattern : modules/facebookconversiontrackingplus/csv/ to a given whitelist
* You should restrict access to .csv file to a given whitelist

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/analytics-statistics/18739-pixel-plus-events-capi-pixel-catalog-for-facebook.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-46352)
