---
layout: post
title: "[CVE-2023-43139] Improper Neutralization of Special Elements used in an OS Command in the Franfinance module for PrestaShop"
categories: modules
author:
- 202 ecommerce.com
- TouchWeb.fr
meta: "CVE,PrestaShop,franfinance"
severity: "critical (10)"
---

The PrestaShop e-commerce platform module Franfinance contains a vulnerability that lets an attaker inject a malicious malware in releases published before 2019.


## Summary

* **CVE ID**: [CVE-2023-43139](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43139)
* **Published at**: 2023-10-25
* **Advisory source**: Friends-of-presta.org
* **Vendor**: PrestaShop
* **Product**: franfinance
* **Impact release**: < 1.9.0 for Prestashop 1.6 OR < 2.0.27 for Prestashop 1.7+
* **Product author**: 202 ecommerce until 2019 / an other developer after
* **Weakness**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
* **Severity**: critical (10)


## Description

The validation of a payment with the Franfinance solution uses Atos SIPS v1 platform which returns data to decrypt with a binary file to execute.

An attacker can inject into this sequence an arbitrary executable script.

### version 1.x

This version is used by PrestaShop 1.6-. The vulnerability can be exploited even if the module is disabled.

### version 2.x

This version is used by PrestaShop 1.7. The vulnerability can be exploited only if the module is enabled.


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

* Control and hijack a PrestaShop

## Patches and recommendations

If the `exec()` method is found in the module especially in file `modules/franfinance/validation.php` or `modules/franfinance/controllers/front/validation.php`, your module used obsolete SIPS V1 and **must be removed**.

## Timeline

| Date | Action |
|--|--|
| 2023-01-13 | Issue discovered during a code review by [TouchWeb.fr](https://touchweb.fr) and documented by [202-ecommerce.com](https://www.202-ecommerce.com/) |
| 2023-01-13 | Security issue report to Franfinance |
| 2023-01-13 | Franfinance confirms the scope of release |
| 2023-09-08 | Request a CVE ID |
| 2023-10-25 | Publication of the security advisory |


## Links

* [PrestaShop addons product page](https://opencredit.franfinance.com/foire-aux-questions/la-mise-en-place-dune-solution-de-facilite-de-paiement/comment-mettre-en-place)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-43139)

