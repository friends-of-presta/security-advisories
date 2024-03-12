---
layout: post
title: "[CVE-2024-28389] Improper neutralization of SQL parameters in Knowband - Entry,Exit and Subscription Popup-Spin and Win module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,spinwheel"
severity: "critical (9.8)"
---

In the module "Entry,Exit and Subscription Popup-Spin and Win" (spinwheel) up to version 3.0.3 from KnowBand for PrestaShop, an anonymous user can perform a SQL injection.


## Summary

* **CVE ID**: [CVE-2024-28389](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28389)
* **Published at**: 2024-03-12
* **Platform**: PrestaShop
* **Product**: spinwheel
* **Impacted release**: <= 3.0.3 (3.0.4 fixed the vulnerability)
* **Product author**: KnowBand
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `SpinWheelFrameSpinWheelModuleFrontController::sendEmail()` has sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

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

## Patch from 3.0.3

```diff
--- 3.0.3/modules/spinwheel/controllers/front/framespinwheel.php
+++ 3.0.4/modules/spinwheel/controllers/front/framespinwheel.php
private static function transactionExists(string
...
-       $sql = 'select slice_type, coupon_value, coupon_type, gift_product from ' . _DB_PREFIX_ . 'wheel_slices where slice_no=' . pSQL($slice_no);
+       $sql = 'select slice_type, coupon_value, coupon_type, gift_product from ' . _DB_PREFIX_ . 'wheel_slices where slice_no=' . (int) $slice_no;
        $query = db::getInstance()->getRow($sql);
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **spinwheel**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-10-20 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-10-20 | Contact PrestaShop Addons security Team to confirm version scope |
| 2023-10-20 | PrestaShop Addons security Team confirm version scope |
| 2024-01-25 | Author provide a patch |
| 2024-03-11 | Received CVE ID |
| 2024-03-12 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/promotions-gifts/28778-knowband-entryexit-and-subscription-popup-spin-and-win.html)
* [Auhtor product page](https://www.knowband.com/fr/prestashop-spin-and-win)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-28389)
