---
layout: post
title: "[CVE-2024-25843] Improper neutralization of SQL parameter in Buy Addons - Import/Update Bulk Product from any Csv/Excel File Pro module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ba_importer"
severity: "critical (9.8)"
---

In the module "Import/Update Bulk Product from any Csv/Excel File Pro" (ba_importer) up to version 1.1.28 from Buy Addons for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2024-25843]
* **Published at**: 2024-02-27
* **Platform**: PrestaShop
* **Product**: ba_importer
* **Impacted release**: <= 1.1.28 (1.1.29 fixed the vulnerability)
* **Product author**: Buy Addons
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `ba_importerAjaxSettingModuleFrontController::run()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

Note : the author has deleted from his module the file which have been suffering from the critical vulnerability for years, BUT did not set them to be "auto-deleted" during upgrades. Therefore, there are likely merchants out there with older versions who have updated their modules, thinking they are safe. However, there is nothing safe about that, since past upgrades did not auto-delete the implicated files. To ensure everyone has a "safe version", we decided to mark all versions up to 1.1.28 as impacted by this issue.


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
curl -v 'https://preprod.X/?fc=module&module=ba_importer&controller=ajaxsetting&ajax=true&value_setting=1;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--'
```

## Patch

This one can impact newer version than 1.0.64, see Note above.

```diff
--- 1.0.64/modules/ba_importer/controllers/front/ajaxsetting.php
+++ XXXXXX/modules/ba_importer/controllers/front/ajaxsetting.php
            $select_import_settings = 'SELECT * FROM ' . _DB_PREFIX_ . 'ba_importer_config ';
-           $select_import_settings .= 'WHERE id_importer_config=' . $settingchoose . ' AND id_shop=' . $id_shop;
+           $select_import_settings .= 'WHERE id_importer_config=' . (int) $settingchoose . ' AND id_shop=' . (int) $id_shop;
```

```diff
--- 1.1.27/modules/ba_importer/autoimport.php
+++ 1.1.29/modules/ba_importer/autoimport.php
...
-$remote_ip = Tools::getRemoteAddr();
-if (!(int)Configuration::get('PS_SHOP_ENABLE')) {
-    if (!in_array($remote_ip, explode(',', Configuration::get('PS_MAINTENANCE_IP')))) {
-        if (!Configuration::get('PS_MAINTENANCE_IP')) {
-            Configuration::updateValue('PS_MAINTENANCE_IP', $remote_ip);
-        } else {
-            Configuration::updateValue('PS_MAINTENANCE_IP', Configuration::get('PS_MAINTENANCE_IP') . ',' . $remote_ip);
-        }
-    }
-}
...
-   $id_importer_config = Tools::getValue('id_importer_config');
+   $id_importer_config = implode(',', array_map('intval', explode(',',  Tools::getValue('id_importer_config'))));
```



## Other recommendations

* It’s recommended to upgrade to the latest version of the module **ba_importer**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-11-14 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-11-14 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-11-14 | PrestaShop Addons security Team confirms version scope |
| 2024-01-12 | Author provide patch |
| 2024-02-22 | Received CVE ID |
| 2024-02-27 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/data-import-export/20579-import-update-bulk-product-from-any-csv-excel-file-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-25843)
