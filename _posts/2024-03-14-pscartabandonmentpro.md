---
layout: post
title: "[CVE-2024-28392] Improper neutralization of SQL parameter in Abandoned Cart Reminder Pro module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,pscartabandonmentpro"
severity: "high (8.8)"
---

In the module "Abandoned Cart Reminder Pro" (pscartabandonmentpro) up to version 2.0.11 from PrestaShop for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2024-28392](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28392)
* **Published at**: 2024-03-14
* **Platform**: PrestaShop
* **Product**: pscartabandonmentpro
* **Impacted release**: <= 2.0.11 (2.0.12 fixed the vulnerability)
* **Product author**: PrestaShop
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: high (8.8)

## Description

The method `pscartabandonmentproFrontCAPUnsubscribeJobModuleFrontController::setEmailVisualized()` has sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admin's ajax scripts
* Rewrite SMTP settings to hijack emails


## Patch from 2.0.11

```diff
--- 2.0.11/modules/pscartabandonmentpro/controllers/front/FrontCAPUnsubscribeJob.php
+++ 2.0.12/modules/pscartabandonmentpro/controllers/front/FrontCAPUnsubscribeJob.php
-       $iCartId = Tools::getValue('id_cart');
-       $iReminderId = Tools::getValue('id_reminder');
+       $iCartId = (int) Tools::getValue('id_cart');
+       $iReminderId = (int) Tools::getValue('id_reminder');
```


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **pscartabandonmentpro**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-11-18 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-11-18 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2024-02-07 | PrestaShop Addons security Team confirms version scope by author |
| 2024-03-11 | Received CVE ID |
| 2024-03-14 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/remarketing-shopping-cart-abandonment/16535-abandoned-cart-reminder-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-28392)
