---
layout: post
title: "[CVE-2024-25840] Improper Limitation of a Pathname to a Restricted Directory in Presta World - Account Manager | Sales Representative & Dealers | CRM module  for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,prestasalesmanager"
severity: "high (7.5), GDPR violation"
---

In the module "Account Manager | Sales Representative & Dealers | CRM" (prestasalesmanager) up to version 8.0.0 from Presta World for PrestaShop, a guest can download personal information without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2024-25840](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25840)
* **Published at**: 2024-02-27
* **Platform**: PrestaShop
* **Product**: prestasalesmanager
* **Impacted release**: <= 8.0.0 (9.0.0 fixed the vulnerability)
* **Product author**: Presta World
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5)

## Description

The method `PrestaSalesManagerChatboxModuleFrontController::postProcess()` has sensitive action that can be executed with a trivial http call and exploited to forge a Path traversal attack.

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


## Patch from 8.0.0

```diff
--- 8.0.0/modules/prestasalesmanager/controllers/front/chatbox.php
+++ 9.0.0/modules/prestasalesmanager/controllers/front/chatbox.php
...
-           $file = Tools::getValue('file');
+           $file = basename(Tools::getValue('file'));
-           $id_ticket = Tools::getValue('id_presta_product_enquiry');
+           $id_ticket = (int) Tools::getValue('id_presta_product_enquiry');
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **prestasalesmanager**.
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop

## Timeline

| Date | Action |
|--|--|
| 2023-10-26 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-10-26 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-10-30 | PrestaShop Addons security Team confirms version scope |
| 2024-01-16 | Author provide patch |
| 2024-02-22 | Received CVE ID |
| 2024-02-27 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/third-party-data-integrations-crm-erp/90816-account-manager-sales-representative-dealers-crm.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-25840)