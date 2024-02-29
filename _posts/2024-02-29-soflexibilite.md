---
layout: post
title: "[CVE-2024-25844] Exposure of Private Personal Information to an Unauthorized Actor in Common-Services - So Flexibilite module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,soflexibilite"
severity: "medium (7.5), GDPR violation"
---

In the module "So Flexibilite" (soflexibilite) up to version 4.1.14 from Common-Services for PrestaShop, a guest can steal login / password to access web portal https://www.colissimo.entreprise.laposte.fr/ and download all customers datas such as name / surname / postal address / phone.

## Summary

* **CVE ID**: [CVE-2024-25844](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25844)
* **Published at**: 2024-02-
* **Platform**: PrestaShop
* **Product**: soflexibilite
* **Impacted release**: <= 4.1.14 (4.1.26 fixed the vulnerability)
* **Product author**: Common-Services
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
* **Severity**: medium (7.5), GDPR violation

## Description

Due to a lack of permissions control, a guest can access debug file (which own no extension so payload will bypass most WAF) from the module which leak the login / password of the web portal https://www.colissimo.entreprise.laposte.fr/, then export all customers data who used this carrier.

Note : there is no version between 4.1.14 and 4.1.26.

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

* It’s recommended to upgrade to the latest version of the module **soflexibilite**.

## Timeline

| Date | Action |
|--|--|
| 2023-08-09 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-08-09 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-09-14 | Author provide a patch |
| 2024-01-24 | PrestaShop Addons security Team confirms version scope by author |


TouchWeb thanks Bryan Bouchut for his help with the impact analysis on the web platform https://www.colissimo.entreprise.laposte.fr/

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/transporteurs/2704-colissimo-domicile-et-points-de-retrait.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-25844)
