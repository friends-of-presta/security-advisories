---
layout: post
title: "[CVE-2025-61922] Customer account takeover via email in PrestaShop Checkout module for PrestaShop"
categories: modules
author:
- PrestaShop SA
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ps_checkout"
severity: "critical (9.1)"
---

Missing validation on Express Checkout feature in the PrestaShop Checkout module allows silent log-in, enabling customer account takeover via email.

## Summary

* **CVE ID**: [CVE-2025-61922](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-61922)
* **Published at**: 2025-10-16
* **Advisory source**: [PrestaShopCorp GitHub Security Advisory](https://github.com/PrestaShopCorp/ps_checkout/security/advisories/GHSA-54hq-mf6h-48xh)
* **Platform**: PrestaShop
* **Product**: ps_checkout
* **Impacted release**: >= 1.3.0, < 4.4.1, < 5.0.5 (see version details below)
* **Product author**: PrestaShop
* **Weakness**: [CWE-358](https://cwe.mitre.org/data/definitions/358.html)
* **Severity**: critical (9.1)

## Description

The issue was introduced in PrestaShop Checkout 1.3.0. A missing validation on the Express Checkout feature allows attackers to perform silent authentication, leading to customer account takeover via email. All versions above 1.3.0 are vulnerable except the patched versions.

**Important note about version numbering**: The first digit of the version displayed in the PrestaShop back office corresponds to the PrestaShop version. Therefore:
- For **PrestaShop 1.7**: versions < 7.5.0.5 require an update
- For **PrestaShop 8**: versions < 8.5.0.5 require an update
- For **PrestaShop 9**: versions < 9.5.0.5 require an update

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Possible malicious usage

* Customer account takeover
* Unauthorized order placement using compromised accounts

## Patches

The problem has been patched in the following versions published on 2025-10-16:

* **v4.4.1** for PrestaShop 1.7 (build number: **7.4.4.1**)
* **v4.4.1** for PrestaShop 8 (build number: **8.4.4.1**)
* **v5.0.5** for PrestaShop 1.7 (build number: **7.5.0.5**)
* **v5.0.5** for PrestaShop 8 (build number: **8.5.0.5**)
* **v5.0.5** for PrestaShop 9 (build number: **9.5.0.5**)

Read the [PrestaShop Checkout Versioning policy](https://github.com/PrestaShopCorp/ps_checkout/wiki/Versioning) to learn more about build numbers and versions.

## Other recommendations

* **It's highly recommended to upgrade the module** to the latest patched version immediately.
* Review your logs for any suspicious authentication activities
* Consider notifying affected customers if you suspect account compromise
* Monitor for unusual order or account activity patterns

## Timeline

| Date | Action |
|--|--|
| 2025-10-16 | Vulnerability patched and versions released |
| 2025-10-16 | Publication of this security advisory |

## Credits

We would like to thank [Léo CUNÉAZ](https://github.com/inem0o) for reporting the issue.

## Links

* [PrestaShop Checkout on PrestaShop Addons](https://addons.prestashop.com/en/payment-card-wallet/46347-prestashop-checkout-built-with-paypal.html)
* [PrestaShopCorp GitHub Security Advisory GHSA-54hq-mf6h-48xh](https://github.com/PrestaShopCorp/ps_checkout/security/advisories/GHSA-54hq-mf6h-48xh)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2025-61922)
