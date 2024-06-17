---
layout: post
title: "[CVE-2024-36677] Exposure of Private Personal Information to an Unauthorized Actor in Weblir - Login as customer PRO module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,loginascustomerpro"
severity: "high (7.5), GDPR violation"
---

In the module "Login as customer PRO" (loginascustomerpro) from Weblir for PrestaShop, a guest can access direct link to connect to each customer account of the Shop if the module is not installed OR if a secret accessible to administrator is stolen..

## Summary

* **CVE ID**: [CVE-2024-36677](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-36677)
* **Published at**: 2024-06-18
* **Platform**: PrestaShop
* **Product**: loginascustomerpro
* **Impacted release**: < 1.2.7 (1.2.7 fixed the vulnerability)
* **Product author**: Weblir
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
* **Severity**: high (7.5), GDPR violation

## Description

*Foreword : we are forced to tag privilege NONE on the CVSS 3.1 score which make it a high vulnerability since it will be high if the module has never been installed OR (if the LOGINASCUSTOMERPRO_TOKEN configuration do not exist OR is empty), but keep in mind that for the majority of installations, the gravity is low*

The script PHP ajax.php allow to exfiltrate links to connect to all customer's accounts.


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


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **loginascustomerpro**.
* You should restrict access to this URI pattern : modules/loginascustomerpro/ajax.php to a given whitelist

## Timeline

| Date | Action |
|--|--|
| 2024-03-13 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2024-03-13 | Contact PrestaShop Addons security Team to confirm version scope by author  |
| 2024-03-13 | PrestaShop Addons security Team confirms version scope by author  |
| 2024-04-12 | Author provide a patch |
| 2024-06-06 | Received CVE ID |
| 2024-06-18 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/social-login-connect/48805-login-as-customer-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-36677)
