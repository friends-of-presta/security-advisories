---
layout: post
title: "[CVE-2023-47308] Improper neutralization of SQL parameter in Active Design - Newsletter Popup PRO with Voucher/Coupon code module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,newsletterpop"
severity: "critical (9.8)"
---

In the module "Newsletter Popup PRO with Voucher/Coupon code" (newsletterpop) up to version 2.6.0 from Active Design for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-47308](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-47308)
* **Published at**: 2023-11-09
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: newsletterpop
* **Impacted release**: >= 2.3.1 & <= 2.4.53 / >= 2.5.2 & <= 2.6.0 (2.6.1 fixed the vulnerability)
* **Product author**: Active Design
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `NewsletterpopsendVerificationModuleFrontController::checkEmailSubscription()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards. 

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

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails


## Proof of concept

```bash
curl -v -d 'fc=modulemodule=newsletterpop&controller=sendVerification&action=checkEmailSubscription&email=%22;select+0x73656C65637420736C656570283432293B+into+@a;prepare+b+from+@a;execute+b;--' 'https://preprod.X'
```

## Patch from 2.5.2

```diff
--- 2.5.2/modules/newsletterpop/controllers/front/sendVerification.php
+++ 2.6.1/modules/newsletterpop/controllers/front/sendVerification.php
...
    public function checkEmailSubscription($email)
    {
        $response = array();
        $module = Module::getInstanceByName('newsletterpop');

        if (Tools::substr(_PS_VERSION_, 0, 3) !== '1.7') {
-           $emailNewsletter = Db::getInstance(_PS_USE_SQL_SLAVE_)->getValue('SELECT `email` FROM `'._DB_PREFIX_.'newsletter` WHERE `email`="'.$email.'"');
+           $emailNewsletter = Db::getInstance(_PS_USE_SQL_SLAVE_)->getValue('SELECT `email` FROM `'._DB_PREFIX_.'newsletter` WHERE `email`="'.pSQL($email).'"');
-           $emailNewsletterPop = Db::getInstance(_PS_USE_SQL_SLAVE_)->getValue('SELECT `email` FROM `'._DB_PREFIX_.'newsletterpop` WHERE `email`="'.$email.'"');
+           $emailNewsletterPop = Db::getInstance(_PS_USE_SQL_SLAVE_)->getValue('SELECT `email` FROM `'._DB_PREFIX_.'newsletterpop` WHERE `email`="'.pSQL($email).'"');
        } else {
-           $emailNewsletter = Db::getInstance(_PS_USE_SQL_SLAVE_)->getValue('SELECT `email` FROM `'._DB_PREFIX_.'emailsubscription` WHERE `email`="'.$email.'"');
+           $emailNewsletter = Db::getInstance(_PS_USE_SQL_SLAVE_)->getValue('SELECT `email` FROM `'._DB_PREFIX_.'emailsubscription` WHERE `email`="'.pSQL($email).'"');
-           $emailNewsletterPop = Db::getInstance(_PS_USE_SQL_SLAVE_)->getValue('SELECT `email` FROM `'._DB_PREFIX_.'newsletterpop` WHERE `email`="'.$email.'"');
+           $emailNewsletterPop = Db::getInstance(_PS_USE_SQL_SLAVE_)->getValue('SELECT `email` FROM `'._DB_PREFIX_.'newsletterpop` WHERE `email`="'.pSQL($email).'"');
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **newsletterpop**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-05-24 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-24 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-05-24 | PrestaShop Addons security Team confirms version scope |
| 2023-10-30 | Recontact PrestaShop Addons security Team about the patch |
| 2023-10-30 | PrestaShop Addons security Team confirms a patch has been published |
| 2023-10-30 | Request a CVE ID |
| 2023-11-08 | Received CVE ID |
| 2023-11-09 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/newsletter-sms/27119-newsletter-popup-pro-with-voucher-coupon-code.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-47308)
