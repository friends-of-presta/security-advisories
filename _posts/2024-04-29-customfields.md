---
layout: post
title: "[CVE-2024-33274] Improper Limitation of a Pathname to a Restricted Directory in FME Modules - Custom Checkout Fields, Add Custom Fields to Checkout module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 2dm.pl
- 202 Ecommerce
meta: "CVE,PrestaShop,customfields"
severity: "high (7.5), GDPR violation"
---

In the module "Custom Checkout Fields, Add Custom Fields to Checkout" (customfields) up to version 2.2.7 from FME Modules for PrestaShop, a guest can download personal information without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2024-33274](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33274)
* **Published at**: 2024-04-29
* **Platform**: PrestaShop
* **Product**: customfields
* **Impacted release**: <= 2.2.7 (2.2.8 fixed the vulnerability)
* **Product author**: FME Modules
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5)

## Description

Due to predictable token and a lack of control in the path name construction, a guest can perform a path traversal to view all files on the information system.

Note : We are forced to tag it as a high gravity due to the CWE type 22 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds admin's ajax script of modules due to [this](https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247)

**WARNING** : This exploit use a base64 payload so it will bypass some WAF. Be informed too that it could be used with a dangerous chain attack based on phar wrapper implicit deserialization (see recommendations below)

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

**WARNING** : Be warned that the last version could still be exploited to exfiltrate files whose path does not contain "php".

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

* It’s recommended to upgrade to the latest version of the module **customfields**.
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop
* Activate OWASP 933's rules against wrapper (including phar wrapper) [OWASP rules to filter "phar://"](https://github.com/coreruleset/coreruleset/blob/e36f27e1429a841e91996f4a521d40c996ec74eb/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf#L213)

## Timeline

| Date | Action |
|--|--|
| 2023-09-01 | Issue discovered during a code review by [2DM](https://2dm.pl/) and [TouchWeb](https://www.touchweb.fr) |
| 2023-09-01 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-09-04 | PrestaShop Addons security Team confirms version scope by author |
| 2023-10-26 | Auhtor provide a patch which is not accepted |
| 2024-03-14 | Auhtor provide a another patch which reduced the scope |
| 2024-04-23 | Received CVE ID |
| 2024-04-29 | Publish this security advisory |


## Links

* [Author product page](https://www.fmemodules.com/en/prestashop-modules/149-add-custom-field-to-product-page.html)
* [PrestaShop addons product page](https://addons.prestashop.com/en/registration-ordering-process/19008-custom-checkout-fields-add-custom-fields-to-checkout.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-33274)
