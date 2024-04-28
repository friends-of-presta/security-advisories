---
layout: post
title: "[CVE-2023-45385] Improper Limitation of a Pathname to a Restricted Directory in Print Shipping Labels Pro module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,pqprintshippinglabels"
severity: "high (7.5)"
---

In the module "Print Shipping Labels Pro" (pqprintshippinglabels) up to version 4.15.0 from ProQuality for PrestaShop, a guest can download personal information without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2023-45385](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45385)
* **Published at**: 2024-04-29
* **Platform**: PrestaShop
* **Product**: pqprintshippinglabels
* **Impacted release**: < 4.15.0 (4.15.0 fixed the vulnerability)
* **Product author**: ProQuality
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5)

## Description

Due to a lack of permissions control and a lack of control in the path name construction, a guest can perform a path traversal to view all files on the information system.

WARNING : We are forced to tag it as a medium gravity due to the CWE type 22 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds admin's ajax script of modules due to this : https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247.


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
* Exfiltrate all modules with all versions to facilitate pentesting
* Stealing table_prefix to greatly facilitate SQL injections for kiddies who don't know how to exploit DBMS design's vulnerabilities or steal database access to login in exposed PHPMyAdmin/Adminer/etc.
* Bypass WAF / htaccess restrictions to read forbidden files (such as logs on predictable paths of banks's modules inside /var/log/)

## Patch from 4.12.0

```diff
--- 4.12.0/modules/pqprintshippinglabels/pdfs/shipping-labels.php
+++ XXXXXX/modules/pqprintshippinglabels/pdfs/shipping-labels.php

-$filename = $_REQUEST['filename'];
+$filename = basename($_REQUEST['filename']);

Be warned that this fix is perfectible. See recommendations below.

## Other recommendations

* You should consider restricting the access of modules/pqprintshippinglabels/pdfs/ to a whitelist or delete the module
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop

## Timeline

| Date | Action |
|--|--|
| 2023-05-19 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-19 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-05-22 | PrestaShop Addons security Team confirm versions scope |
| 2023-10-12 | Received CVE ID |
| 2024-02-08 | Author provide a patch (confirmed on 2024-04-10) |
| 2024-04-29 | Publish this security advisory |

## Links

* [Author download page](https://addons.prestashop.com/en/preparation-shipping/16885-print-shipping-labels-pro-address-direct-print.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45385)
