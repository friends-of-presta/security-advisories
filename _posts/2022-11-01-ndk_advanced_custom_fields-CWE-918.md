---
layout: post
title: "[CVE-2022-40842] Server-Side Request Forgery (SSRF) NdkAdvancedCustomizationFields from ndk design a module for PrestaShop"
categories: modules
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ndk_advanced_custom_fields"
severity: "critical (9.1)"
---

In NdkAdvancedCustomizationFields module for PrestaShop before 4.1.7, an anonymous user can perform a Server-Side Request Forgery (SSRF) in affected versions. 4.1.7 fixed the vulnerability.

## Summary

* **CVE ID**: [CVE-2022-40842](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40842)
* **Published at**: 2022-11-01
* **Advisory source**: [@daaaalllii](https://github.com/daaaalllii/cve-s/blob/main/CVE-2022-40839/poc.txt)
* **Platform**: PrestaShop
* **Product**: ndk_advanced_custom_fields
* **Impacted release**: <= 4.1.6 (4.1.7 fixed the vulnerability)
* **Product author**: ndk design
* **Weakness**: [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
* **Severity**: critical (9.1)

## Description

In the NdkAdvancedCustomizationFields module for PrestaShop up to version 4.1.6, an improper validation of `loc` parameter in the `rotateimg.php` script can be executed via a trivial HTTP call to forge Server-Side Request. This vulnerability can be exploited to initiate a blind HTTP request, for instance, use the vulnerable website as proxy to attack others websites.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Possible malicious usage

* Attack others websites via the vulnerability
* Bypass WAF/.htaccess restrictions


## Proof of concept


```bash
http://localhost/modules/ndk_advanced_custom_fields/rotateimg.php?loc=SSRF_PAYLOAD&rot=90&top=1000&left=1000&width=1000&height=1000&imgwidth=1000
```

## Patch

Remove the file or apply this patch :

```diff
--- a/modules/ndk_advanced_custom_fields/rotateimg.php
+++ b/modules/ndk_advanced_custom_fields/rotateimg.php
<?php
+ die();
```


## Other recommandations

* It’s recommended to upgrade the module beyong 4.1.7.
* Activate OWASP 931's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 01-11-2022 | GitHub Poc |
| 26-07-2023 | Publish this advisory on [security](https://security.friendsofpresta.org/) |

## Links

* [Source of this CVE](https://github.com/daaaalllii/cve-s/blob/main/CVE-2022-40842/poc.txt)
* [National Vulnerability Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40842)

