---
layout: post
title: "[CVE-2024-36682] Exposure of Private Personal Information to an Unauthorized Actor in Promokit.eu - Theme settings module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202-ecommerce.com
meta: "CVE,PrestaShop,pk_themesettings"
severity: "high (7.5), GDPR violation"
---

In the module "Theme settings" (pk_themesettings) from Promokit.eu for PrestaShop, a guest can download all emails collected while SHOP is in maintenance mode.

## Summary

* **CVE ID**: [CVE-2024-36682](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-36682)
* **Published at**: 2024-06-20
* **Platform**: PrestaShop
* **Product**: pk_themesettings
* **Impacted release**: <= 1.8.8 (see WARNING below)
* **Product author**: Promokit.eu
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
* **Severity**: high (7.5), GDPR violation

## Description

Due to a lack of permission control, a guest can access the txt file which collect emails when maintenance is enable which can lead to leak of personal information.

**WARNING** : Versions declared as impacted are versions where we confirmed critical issue. Author don't know which exacts versions are impacted, he only said us that it was a long time ago. Author refuse to provide the last version to let us check that all is fixed. So you should consider that all versions can be impacted.

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
| 2024-03-30 | Issue discovered during a code review by [TouchWeb](https://www.touchweb.fr) |
| 2024-03-30 | Contact Author to confirm version scope |
| 2024-03-30 | Author don't know which version is impacted but confirm us that it was a long time ago |
| 2024-03-30 | Author refuse to provide us the last version to check if it is fixed |
| 2024-06-06 | Received CVE ID |
| 2024-06-20 | Publish this security advisory |

## Links

* [Author product page](https://promokit.eu/)
* [Theme forest author page](https://themeforest.net/user/promokit)
* [Theme forest product page](https://themeforest.net/item/alysum-premium-responsive-prestashop-16-theme/2622574)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-36682)
