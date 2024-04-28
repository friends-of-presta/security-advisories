---
layout: post
title: "[CVE-2024-33267] Improper neutralization of SQL parameter in Hero - Payment module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,hfheropayment"
severity: "critical (9.8)"
---

In the module "Hero - Payment" (hfheropayment) up to version 1.2.5 from Hero for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2024-33267](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33267)
* **Published at**: 2024-04-29
* **Platform**: PrestaShop
* **Product**: hfheropayment
* **Impacted release**: <= 1.2.5 (1.2.6 fixed the vulnerability)
* **Product author**: Hero
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `HfHeropaymentGatewayBackModuleFrontController::initContent()` has a sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : This exploit use a base64 payload so it will bypass some WAF.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.


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

## Patch from 1.2.5

```diff
--- 1.2.5/modules/hfheropayment/controllers/front/gatewayback.php
+++ XXXXX/modules/hfheropayment/controllers/front/gatewayback.php
            $id = Db::getInstance()->getValue(
                "SELECT hf_payment_id FROM `" . _DB_PREFIX_ . "cart_hf_heropayment`
-                    WHERE id='" . $insertId . "'"
+                    WHERE id='" . (int) $insertId . "'"
            );
```


## Other recommendations

* It’s recommended to delete this module **hfheropayment**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2024-03-05 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2024-03-05 | Contact Author to confirm version scope by author |
| 2024-03-05 | Author confirms version scope by author |
| 2024-03-14 | Author provide a patch |
| 2024-04-23 | Received CVE ID |
| 2024-04-29 | Publish this security advisory |

## Links

* [Authro Product page](https://www.heropay.eu/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-33267)