---
layout: post
title: "[CVE-2024-25842] External Control of File Name or Path in Presta World - Account Manager - Sales Representative & Dealers - CRM module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- Algo-Factory.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,prestasalesmanager"
severity: "critical (9.1)"
---

In the module "Account Manager - Sales Representative & Dealers - CRM" (prestasalesmanager) up to version 8.0.0 from Presta World for PrestaShop, a guest can delete all files of the system.


## Summary

* **CVE ID**: [CVE-2024-25842](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25842)
* **Published at**: 2024-02-29
* **Platform**: PrestaShop
* **Product**: prestasalesmanager
* **Impacted release**: <= 8.0.0 (9.0.0 fixed the vulnerability)
* **Product author**: Presta World
* **Weakness**: [CWE-73](https://cwe.mitre.org/data/definitions/73.html)
* **Severity**: critical (9.1)

## Description

Methods `PrestaSalesManagerChatboxModuleFrontController::uploadLogo()` and `PrestaSalesManagerMyAccountManagerTabModuleFrontController::postProcess` has sensitive fopen call that can be executed with a trivial http call and exploited to delete all files of the system.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: none
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)

## Possible malicious usage

* Delete all files from the Shop
* Disable critical security configuration (.htaccess) to access private zone

## Patch from 8.0.0

```diff
--- 8.0.0/modules/prestasalesmanager/controllers/front/chatbox.php
+++ 9.0.0/modules/prestasalesmanager/controllers/front/chatbox.php
...
-           $idTicket = Tools::getValue('id_enquiry');
+           $idTicket = (int) Tools::getValue('id_enquiry');
```

```diff
--- 8.0.0/modules/prestasalesmanager/controllers/front/myaccountmanagertab.php
+++ 9.0.0/modules/prestasalesmanager/controllers/front/myaccountmanagertab.php
...
-           $idHelpDesk = Tools::getValue('id_helpDesk');
+           $idHelpDesk = (int) Tools::getValue('id_helpDesk');
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **prestasalesmanager**.
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop


## Timeline

| Date | Action |
|--|--|
| 2023-10-26 | Issue discovered during a code review by [TouchWeb](https://www.touchweb.fr) and [Algo Factory](https://www.algo-factory.com/) |
| 2023-10-26 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-10-30 | PrestaShop Addons security Team confirms version scope |
| 2024-01-16 | Author provide patch |
| 2024-02-22 | Received CVE ID |
| 2024-02-29 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/third-party-data-integrations-crm-erp/90816-account-manager-sales-representative-dealers-crm.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-25842)
