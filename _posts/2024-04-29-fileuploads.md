---
layout: post
title: "[CVE-2024-33270] Exposure of Private Personal Information to an Unauthorized Actor in FME Modules - Customer File Upload-Attach File on Product,Cart pages module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 ecommerce.com
meta: "CVE,PrestaShop,fileuploads"
severity: "high (7.5), GDPR violation"
---

In the module "Customer File Upload-Attach File on Product,Cart pages" (fileuploads) up to version 2.0.3 from FME Modules for PrestaShop, a guest can download personal information without restriction.

## Summary

* **CVE ID**: [CVE-2024-33270](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33270)
* **Published at**: 2024-04-29
* **Platform**: PrestaShop
* **Product**: fileuploads
* **Impacted release**: <= 2.0.3 (2.0.4 fixed the vulnerability)
* **Product author**: FME Modules
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
* **Severity**: high (7.5), GDPR violation

## Description

Due to a lack of permissions control, a guest can download all files uploaded by customers which could be national identity card / contents under NDA, etc.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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
| 2023-09-01 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-09-01 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-09-04 | PrestaShop Addons security Team confirms version scope by author |
| 2024-03-14 | Author provide a patch |
| 2024-04-23 | Received CVE ID |
| 2024-04-29 | Publish this security advisory |


## Links

* [Author product page](https://www.fmemodules.com/en/prestashop-modules/80-file-uploads.html)
* [PrestaShop addons product page](https://addons.prestashop.com/en/additional-information-product-tab/21373-customer-file-upload-attach-file-on-productcart-pages.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-33270)
