---
layout: post
title: "[CVE-2023-30198] Improper Limitation of a Pathname to a Restricted Directory in Webbax - Winbiz Payment module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,winbizpayment"
severity: "high (7.5), GDPR violation"
---

In the module "Winbiz Payment" (winbizpayment) from Webbax for PrestaShop, a guest can download personal informations without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2023-30198](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30198)
* **Published at**: 2023-06-08
* **Platform**: PrestaShop
* **Product**: winbizpayment
* **Impacted release**: <= 17.1.3 (17.1.4 should fix the vulnerability - see Note below)
* **Product author**: Webbax
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5), GDPR violation

## Description

Due to a lack of permissions control and a lack of control in the path name construction, a guest can perform a path traversal to view all files on the information system.

WARNING : We are forced to tag it as a medium gravity due to the CWE type 22 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds admin's ajax script of modules due to [this](https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247).

Note: The author refuses to confirm the scope of the vulnerability for his module (we see the vulnerability only in version 1.0.2). However, since he patched the same type of vulnerability in three other modules on May 2, 2023, we reasonably believe that he also patched this module, as it received an update on the same date.

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

* Stealing secrets to unlock admin controllers based on ajax script
* Exfiltrate all modules with all versions to facilite pentesting
* Stealing table_prefix to greatly facilitate SQL injections for kiddies who don't know how exploit DBMS design's vulnerabilities or steal database access to login in exposed PHPMyAdmin / Adminer / etc.
* Bypass WAF / htaccess restrictions to read forbidden files (such as logs on predictable paths of banks's modules inside /var/log/)


## Patch from 17.1.3

```diff
--- 17.1.3/modules/winbizpayment/downloads/download.php
+++ XXXXXX/modules/winbizpayment/downloads/download.php
- $file = Tools::getValue('file');
+ $file = basename(Tools::getValue('file'));
```

Be warned that this fix is perfectible. See recommandations below.

## Other recommendations

* You should consider restricting the access of modules/winbizpayment/downloads/ to a whitelist or delete the module
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop

## Timeline

| Date | Action |
|--|--|
| 2023-02-25 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-02-25 | Contact Author |
| 2023-02-25 | Request a CVE ID |
| 2023-02-27 | Author confirms alert's read |
| 2023-04-24 | Received CVE ID |
| 2023-05-02 | Author publishs a new version which should fix the leak |
| 2023-06-08 | Publish this security advisory |

## Links

* [Author download page](https://shop.webbax.ch/modules-pour-winbiz/136-module-prestashop-winbiz-payment.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-30198)
