---
layout: post
title: "[CVE-2024-28386] Improper Neutralization of Special Elements used in an OS Command in the Home-Made.io - FastMag Sync module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 ecommerce.com
meta: "CVE,PrestaShop,fastmagsync"
severity: "critical (10)"
---

In the module "Fast Mag Sync" (fastmagsync) up to version 1.7.51 from Home-Made.io for PrestaShop, a guest can inject into script an arbitrary executable script.


## Summary

* **CVE ID**: [CVE-2024-28386](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28386)
* **Published at**: 2024-03-19
* **Advisory source**: Friends-of-presta.org
* **Platform**: PrestaShop
* **Product**: fastmagsync
* **Impact release**: <= 1.7.51 (1.7.53 fixed the vulnerability)
* **Product author**: Home-Made.io
* **Weakness**: [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
* **Severity**: critical (10)


## Description

The function `getPhpBin()` do not properly sanitize output, an attacker can inject into this sequence an arbitrary executable script.


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

* Control and hijack a PrestaShop

## Patch from 1.7.51

```diff
--- 1.7.51/modules/fastmagsync/crons/common.php
+++ XXXXXX/modules/fastmagsync/crons/common.php
...
        $get_version = explode('.', $hosting);
        if (count($get_version) > 1) {
            array_shift($get_version);
+           if(preg_match('/[\d]\.[\d]/i',implode('.', $get_version))){
-           $php_version = implode('.', $get_version);
+              $php_version = implode('.', $get_version);
+           }
        }
        $php_bin = '/usr/local/php' . $php_version . '/bin/php';
```


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **fastmagsync**.
* Activate OWASP 932's and 933's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-10-28 | Issue discovered during a code review by [TouchWeb.fr](https://touchweb.fr) |
| 2023-10-28 | Contact Author to confirm version scope |
| 2023-10-28 | Author confirms version scope and provide a patch |
| 2024-03-11 | Received CVE ID |
| 2024-03-19 | Publish this security advisory |


## Links

* [Author product page](https://www.home-made.io/module-fastmag-sync-prestashop/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-28386)

