---
layout: post
title: "[CVE-2024-33836] Unrestricted Upload of File with Dangerous Type in JA Marketplace module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,jamarketplace"
severity: "critical (10)"
---

In the module "JA Marketplace" (jamarketplace) up to version 9.0.1 from JA Module for PrestaShop, a guest can upload files with extensions .php.


## Summary

* **CVE ID**: [CVE-2024-33836](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33836)
* **Published at**: 2024-06-18
* **Platform**: PrestaShop
* **Product**: jamarketplace
* **Impacted release**: <= 9.0.1 (9.0.2 fixed the vulnerability)
* **Product author**: JA Module
* **Weakness**: [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
* **Severity**: critical (10)

## Description

In version 6.X, the method `JmarketplaceproductModuleFrontController::init()` and in version 8.X, the method `JmarketplaceSellerproductModuleFrontController::init()` allow upload of .php files, which will lead to a critical vulnerability [CWE-94](https://cwe.mitre.org/data/definitions/94.html).

**This exploit is actively exploited in the wild**

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: changed
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Steal data


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **jamarketplace**.
* Activate OWASP 933's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-05-27 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-27 | Contact PrestaShop Addons security Team to confirm version scope |
| 2023-05-27 | PrestaShop Addons security Team confirms version scope |
| 2024-05-03 | Received CVE ID |
| 2024-06-18 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/creation-marketplace/18656-ja-marketplace.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-33836)
