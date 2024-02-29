---
layout: post
title: "[CVE-2024-26469] Server-Side Request Forgery (SSRF) in Tunis Soft - Product Designer for PrestaShop"
categories: modules
author:
- Tunis Soft
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,productdesigner"
severity: "critical (9.1)"
---

In the module "Product Designer" (productdesigner) up to version 1.178.36 from Tunis Soft for PrestaShop, an anonymous user can perform a Server-Side Request Forgery (SSRF) in affected versions.

## Summary

* **CVE ID**: [CVE-2024-26469](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26469)
* **Published at**: 2024-02-29
* **Platform**: PrestaShop
* **Product**: productdesigner
* **Impacted release**: < 1.178.36 (1.178.36 fixed the vulnerability)
* **Product author**: Tunis Soft
* **Weakness**: [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
* **Severity**: critical (9.1)

## Description

In the Product Designer module from Tunis Soft for PrestaShop, an improper validation of `url` parameter in the method `ProductDesignerPixabayModuleFrontController::postProcess` can be executed via a trivial HTTP call to forge Server-Side Request. 

This vulnerability can be exploited to initiate a HTTP request and get the return, for instance, use the vulnerable website as proxy to attack others websites, exfiltrate data in files under IP restriction or perform a path traversal attack.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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
* Perform path traversal attack

## Other recommendations

* It’s recommended to upgrade the module to its latest version
* Activate OWASP 930 and 931's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-09-30 | Issue discovered during a code review by [TouchWeb](https://www.touchweb.fr/) |
| 2023-09-30 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-10-25 | PrestaShop Addons security Team confirms version scope |
| 2023-11-07 | Author provide a patch |
| 2024-02-22 | Received CVE ID |
| 2024-02-29 | Publish this security advisory |

Tunis Soft thanks [TouchWeb](https://www.touchweb.fr) for its courtesy and its help after the vulnerability disclosure.

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/combinaisons-customization/30176-product-designer.html)
* [National Vulnerability Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26469)

