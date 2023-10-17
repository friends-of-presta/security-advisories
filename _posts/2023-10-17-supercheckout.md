---
layout: post
title: "[CVE-2023-45384] Unrestricted Upload of File with Dangerous Type in One Page Checkout, Social Login & Mailchimp module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,supercheckout"
severity: "critical (10)"
---

In the module "Module One Page Checkout, Social Login & Mailchimp" (supercheckout) up to version 6.0.6 from KnowBand for PrestaShop, a guest can upload dangerous files with extensions .php.


## Summary

* **CVE ID**: [CVE-2023-45384]
* **Published at**: 2023-10-17
* **Platform**: PrestaShop
* **Product**: supercheckout
* **Impacted release**: <= 6.0.6 (6.0.7 fixed the vulnerability)
* **Product author**: KnowBand
* **Weakness**: [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
* **Severity**: critical (10)

## Description

The method `SupercheckoutSupercheckoutModuleFrontController::saveFileTypeCustomField()` allow upload of .php files, which will lead to a critical vulnerability [CWE-94](https://cwe.mitre.org/data/definitions/94.html).

**This exploit is actively exploited in the wild**

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: changed
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Steal datas

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **supercheckout**.
* Activate OWASP 933's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-05-25 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-25 | Contact PrestaShop Addons security Team to confirm version scope |
| 2023-05-25 | PrestaShop Addons security Team confirm version scope |
| 2023-06-06 | Request a CVE ID |
| 2023-10-11 | Received CVE ID |
| 2023-10-17 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/processus-rapide-commande/18016-one-page-checkout-social-login-mailchimp.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45384)
