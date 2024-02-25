---
layout: post
title: "[CVE-2024-24307] Improper Limitation of a Pathname to a Restricted Directory in Tunis Soft - Product Designer module  for PrestaShop"
categories: modules
author:
- Tunis Soft
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,productdesigner"
severity: "high (7.5), GDPR violation"
---

In the module "Product Designer" (productdesigner) up to version 1.178.36 from Tunis Soft for PrestaShop, a guest can download personal information without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2024-24307](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24307)
* **Published at**: 2024-02-29
* **Platform**: PrestaShop
* **Product**: productdesigner
* **Impacted release**: < 1.178.36 (1.178.36 fixed the vulnerability)
* **Product author**: Tunis Soft
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5)

## Description

The method `ProductDesignerUserUploadModuleFrontController::ajaxProcessCropImage()` has sensitive action that can be executed with a trivial http call and exploited to forge a Path traversal attack.

Note : We are forced to tag it as a high gravity due to the CWE type 22 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds admin's ajax script of modules due to [this](https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247)

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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
* Stealing table_prefix to greatly facilitate SQL injections for kiddies who don't know how to exploit DBMS design's vulnerabilities or steal database access to login in exposed PHPMyAdmin / Adminer / etc.
* Bypass WAF / htaccess restrictions to read forbidden files (such as logs on predictable paths of banks's modules inside /var/log/)


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **productdesigner**.
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop

## Timeline

| Date | Action |
|--|--|
| 2023-11-07 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-11-07 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-11-07 | PrestaShop Addons security Team confirms version scope |
| 2023-11-08 | Author provide a patch |
| 2024-02-05 | Received CVE ID |
| 2024-02-29 | Publish this security advisory |

Tunis Soft thanks [TouchWeb](https://www.touchweb.fr) for its courtesy and its help after the vulnerability disclosure.


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/combinaisons-customization/30176-product-designer.html)
* [National Vulnerability Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24307)