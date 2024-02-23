---
layout: post
title: "[CVE-2023-46358] Improper neutralization of SQL parameter in Snegurka - Referral and Affiliation Program module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,referralbyphone"
severity: "critical (9.8)"
---

In the module "Referral and Affiliation Program" (referralbyphone) up to 3.5.1 (all versions - see WARNING) from Snegurka for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-46358](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46358)
* **Published at**: 2023-10-24
* **Platform**: PrestaShop
* **Product**: referralbyphone
* **Impacted release**: <= 3.5.1 (WARNING : The author has not fixed the vulnerability)
* **Product author**: Snegurka
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Method `ReferralByPhoneDefaultModuleFrontController::ajaxProcessCartRuleValidate` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards.

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
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails


## Proof of concept

```bash
curl -v -d 'fc=modulemodule=referralbyphone&controller=default&action=CartRuleValidate&ws_voucher=%27;select+0x73656C65637420736C656570283432293B+into+@a;prepare+b+from+@a;execute+b;--' 'https://preprod.X'
```


## Patch from 3.5.1

```diff
--- 3.5.1/modules/referralbyphone/controllers/front/default.php
+++ XXXXX/modules/referralbyphone/controllers/front/default.php
        $id_ws_sponsor = Db::getInstance(_PS_USE_SQL_SLAVE_)->getValue(
-           'SELECT `id_ws_sponsor` FROM `' . _DB_PREFIX_ . 'ws_ref_coupon_rule` WHERE `code` = \'' . $ws_voucher . '\''
+           'SELECT `id_ws_sponsor` FROM `' . _DB_PREFIX_ . 'ws_ref_coupon_rule` WHERE `code` = \'' . pSQL($ws_voucher) . '\''
        );
```

## Other recommendations

* It’s recommended to delete the module since author no longer maintain it.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-07-20 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-07-20 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-07-20 | PrestaShop Addons security Team confirm versions scope |
| 2023-08-22 | Contact the author again for a fix |
| 2023-10-19 | Contact the author again for a fix |
| 2023-10-19 | PrestaShop Addons security Team confirms that the author has not yet produced a patch |
| 2023-10-20 | Request a CVE ID |
| 2023-10-23 | Received CVE ID |
| 2023-10-24 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/sea-paid-advertising-affiliation-platforms/19203-referral-and-affiliation-program.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-46358)
