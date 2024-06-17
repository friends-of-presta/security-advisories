---
layout: post
title: "[CVE-2024-36679] Improper Control of Generation of Code in Module Live Chat Pro (All in One Messaging) module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
meta: "CVE,PrestaShop,livechatpro"
severity: "critical (10.0)"
---

In the module "Module Live Chat Pro (All in One Messaging)" (livechatpro), a guest can perform PHP Code injection in affected versions.

## Summary

* **CVE ID**: [CVE-2024-36679](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-36679)
* **Published at**: 2024-06-18
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: livechatpro
* **Impacted release**: <= 8.4.0 [WAITING FOR VERSION SCOPE BY AUHOR]
* **Product author**: ProQuality
* **Weakness**: [CWE-94](https://cwe.mitre.org/data/definitions/94.html)
* **Severity**: critical (10.0)

## Description

Due to a predictable token, the method `Lcp::saveTranslations()` suffer of a white writer that can inject PHP code into a PHP file which will lead to critical RCE.

Author refuse to patch the vulnerability so you should consider to uninstall it. There is strong design issue which cannot be fix by a hotfix.

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
* Complete takeover

## Other recommendations

* It’s recommended to delete this module.
* Activate OWASP 933's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-05-24 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-24 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-05-24 | PrestaShop Addons security Team confirms version scope by author |
| 2023-10-02 | Relaunch for patch |
| 2024-04-17 | Relaunch for patch |
| 2024-05-29 | PrestaShop Addons put offline the module |
| 2024-06-06 | Received CVE ID |
| 2024-06-18 | Publish this security advisory |



## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/support-chat-online/18967-live-chat-pro-all-in-one-messaging.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-36679)
