---
layout: post
title: "[CVE-2024-33266] Improper neutralization of SQL parameter in Helloshop - Tracking Center - Parcel tracking 80 carriers module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,deliveryorderautoupdate"
severity: "critical (9.8)"
---

In the module "Tracking Center - Parcel tracking 80 carriers" (deliveryorderautoupdate) up to version 2.8.2 from Helloshop for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2024-33266](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33266)
* **Published at**: 2024-04-25
* **Platform**: PrestaShop
* **Product**: deliveryorderautoupdate
* **Impacted release**: <= 2.8.1 (2.8.2 fixed the vulnerability)
* **Product author**: Helloshop
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Ajax script ajax_email.php, all scripts in directory webservices/ and the method `DeliveryorderautoupdateOrdersModuleFrontController::initContent()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : One of exploits (against ajax_email.php) is actively used to deploy a webskimmer to massively steal credit cards.

Note : the author has deleted from his module one of the files (ajax_email.php) which have been suffering from critical vulnerabilities for years, BUT did not set them to be "auto-deleted" during upgrades. Therefore, there are likely merchants out there with older versions who have updated their modules, thinking they are safe. However, there is nothing safe about that, since past upgrades did not auto-delete the implicated files. To ensure everyone has a "safe version", we decided to mark all versions up to 2.8.1 as impacted by this issue.

**DANGER** : Patch provided are partial - since there is more than 100 critical issues inside the directory webservices/, we do not provide patch - put the directory under IP restriction without delay or upgrade the module.

One of exploits uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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


## Proof of concept

PUBLIC POC - seen on 2.2.2- (and potentially newer since author did not auto deleted file)

```bash
curl -v 'https://preprod.X/modules/deliveryorderautoupdate/ajax_email.php?lang=1;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--'
```

## Patch from 2.2.2

This one can impact newer version than 2.2.2, see Note above.

```diff
--- 2.2.2/modules/deliveryorderautoupdate/ajax_email.php
+++ XXXXX/modules/deliveryorderautoupdate/ajax_email.php
...
    $lang = Db::getInstance()->getRow(
-       'SELECT iso_code FROM '._DB_PREFIX_.'lang WHERE id_lang='.Tools::getValue('lang')
+       'SELECT iso_code FROM '._DB_PREFIX_.'lang WHERE id_lang='.(int) Tools::getValue('lang')
```

## Patch from 2.8.1

```diff
--- 2.8.1/modules/deliveryorderautoupdate/controllers/front/orders.php
+++ XXXXX/modules/deliveryorderautoupdate/controllers/front/orders.php
...
        if (Tools::isSubmit('id_email')) {
-           $id_email =  Tools::getValue('id_email');
+           $id_email =  (int) Tools::getValue('id_email');
            $order = Order::getByReference($id)->getFirst();
            if ($order) {
                $id_order = $order->id;
                Db::getInstance()->update('hl_tracking_email', array(
                    'email_status' => 3,
-               ), "id = {$id_email} AND id_order = {$id_order}");
+               ), "id = ". $id_email . " AND id_order = " . (int) $id_order);
            }
        }
```


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **deliveryorderautoupdate**.
* You should restrict access to modules/deliveryorderautoupdate/webservices/ to a given whitelist
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-11-13 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) and by [202 ecommerce](https://www.202-ecommerce.com/) |
| 2023-11-13 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-11-13 | PrestaShop Addons security Team confirms version scope |
| 2024-01-25 | Author provide a patch |
| 2024-04-23 | Received CVE ID |
| 2024-04-25 | Publish this security advisory |

## Links

* [Author product page](https://helloshop.com/fr/modules-pour-prestashop/2-module-tracking-center-pour-prestashop.html)
* [PrestaShop addons product page](https://addons.prestashop.com/en/delivery-tracking/22347-tracking-center-parcel-tracking-80-carriers.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-33266)
