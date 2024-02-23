---
layout: post
title: "[CVE-2023-40923] Improper neutralization of an SQL parameter in MyPrestaModules - Orders (CSV, Excel) Export PRO module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ordersexport"
severity: "critical (9.8)"
---

In the module "Orders (CSV, Excel) Export PRO" (ordersexport) from MyPrestaModules for PrestaShop, an anonymous user can perform SQL injection up to 5.0. Release 5.0 fixed this security issue.

## Summary

* **CVE ID**: [CVE-2023-40923](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-40923)
* **Published at**: 2023-11-09
* **Advisory source**: Friends-Of-Presta.org
* **Vendor**: PrestaShop
* **Product**: ordersexport
* **Impacted release**: < 5.0 (5.0 fixed the vulnerability)
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Before 5.0, sensitives SQL calls in class `send.php` can be executed with a trivial http call and exploited to forge a blind SQL injection throught the POST or GET submitted "key" or "save_setting" variables.


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
* Steal/Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch

```diff
--- a/ordersexport/send.php
+++ b/ordersexport/send.php
@@ -170,7 +170,7 @@ try {
     $config = array();
     $config = Tools::unserialize(Configuration::get('GOMAKOIL_EXPORT_ORDERS_SETTINGS','', $default_shop_group_id, $default_shop_id));
     $key = Tools::getValue('key');
-    Db::getInstance()->delete('exported_order', 'settings="'.trim($key).'"');
+    Db::getInstance()->delete('exported_order', 'settings="'.pSQL($key).'"');
     unset($config[trim($key)]);
     $config_save =serialize($config);
     Configuration::updateValue('GOMAKOIL_EXPORT_ORDERS_SETTINGS', $config_save, false, $default_shop_group_id, $default_shop_id);
@@ -314,7 +314,7 @@ try {
       $automatic = Tools::getValue('automatic');
       $not_exported = Tools::getValue('not_exported');
       if(isset($automatic) && $automatic && isset($not_exported) && $not_exported ){
-        Db::getInstance()->delete('exported_order', 'settings="'.trim(Tools::getValue('save_setting')).'"');
+        Db::getInstance()->delete('exported_order', 'settings="'.pSQL(Tools::getValue('save_setting')).'"');
       }
       $json['success'] = $ordersexport->l('Data successfully saved!', 'send');
     }
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **ordersexport**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2022-10-09 | Issue discovered during a code reviews by 202 ecommerce |
| 2022-10-10 | Contact the author |
| 2022-10-10 | The author confirm the latest release is already fixed |
| 2023-08-15 | Request a CVE ID |
| 2023-10-11 | Received CVE ID |
| 2023-11-09 | Publication of this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/data-import-export/17596-orders-csv-excel-export-pro.html)
* [National Vulnerability Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-40923)

