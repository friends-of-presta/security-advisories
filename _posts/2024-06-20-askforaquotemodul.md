---
layout: post
title: "[CVE-2024-34988] Improper neutralization of SQL parameter in Buy Addons - Complete for Create a Quote in Frontend + Backend Pro module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202-ecommerce.com
meta: "CVE,PrestaShop,askforaquotemodul"
severity: "critical (9.8)"
---

In the module "Complete for Create a Quote in Frontend + Backend Pro" (askforaquotemodul) up to version 1.0.52 from Buy Addons for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2024-34988](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-34988)
* **Published at**: 2024-06-20
* **Platform**: PrestaShop
* **Product**: askforaquotemodul
* **Impacted release**: <= 1.0.51 (1.0.52 fixed the vulnerability - see WARNING below)
* **Product author**: Buy Addons
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Methods `AskforaquotemodulcustomernewquoteModuleFrontController::run()`, `AskforaquotemoduladdproductnewquoteModuleFrontController::run()`, `AskforaquotemodulCouponcodeModuleFrontController::run()`, `AskforaquotemodulgetshippingcostModuleFrontController::run()`, `AskforaquotemodulgetstateModuleFrontController::run()` has sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

**WARNING** : this version still has sensitives vulnerabilities such as IDOR.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admin's ajax scripts
* Rewrite SMTP settings to hijack emails


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **askforaquotemodul**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-11-14 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-11-14 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-11-14 | PrestaShop Addons security Team confirms version scope |
| 2024-01-11 | Author provide a patch |
| 2024-05-15 | Received CVE ID |
| 2024-06-20 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/data-import-export/20579-import-update-bulk-product-from-any-csv-excel-file-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-34988)
