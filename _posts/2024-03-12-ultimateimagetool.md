---
layout: post
title: "[CVE-2024-28390] Improper Access Control in Advanced Plugins - Image: WebP, Compress, Zoom, Lazy load, Alt & More module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,ultimateimagetool"
severity: "critical (9.1)"
---

In the module "Image: WebP, Compress, Zoom, Lazy load, Alt & More" (ultimateimagetool) in versions up to 2.2.01 from Advanced Plugins for PrestaShop, a guest can update all configurations of the PrestaShop.

## Summary

* **CVE ID**: [CVE-2024-28390](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28390)
* **Published at**: 2024-03-12
* **Platform**: PrestaShop
* **Product**: ultimateimagetool
* **Impacted release**: < 2.2.01 (2.2.01 fixed the vulnerability)
* **Product author**: Advanced Plugins
* **Weakness**: [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
* **Severity**: critical (9.1)

## Description

Due to a predictable token, a guest can update all configurations of the PrestaShop.

Be warned that the author do not follow a compliant semver version.

Note : the author has deleted from his module the files that have been suffering from critical vulnerabilities for months, BUT did not set them to be "auto-deleted" during upgrades. Therefore, there are likely merchants out there with older versions who have updated their modules, thinking they are safe. However, there is nothing safe about that, since past upgrades did not auto-delete the implicated files. To ensure everyone has a "safe version", we decided to mark all versions up to 2.2.01 as impacted by this issue.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: none
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)

## Possible malicious usage

* Erase/update all configurations from the PrestaShop
* Disable critical security configuration

# Other recommendations

* It’s recommended to upgrade to the latest version of the module **ultimateimagetool**.
* You should consider updating the configuration uit_token for something not predictable

## Timeline

| Date | Action |
|--|--|
| 2023-07-22 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-07-22 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2024-01-24 | Contact PrestaShop Addons security Team confirms version scope by author |
| 2024-01-27 | Author provide a "complete" patch which auto-delete old file from previous version |
| 2024-03-11 | Received CVE ID |
| 2024-03-12 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/visuels-produits/27669-image-webp-compression-regeneration.html)
* [Author product page](https://advancedplugins.com/prestashop/modules/image-toolbox-compress-regenerate-more/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-28390)
