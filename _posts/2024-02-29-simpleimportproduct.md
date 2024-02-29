---
layout: post
title: "[CVE-2024-25847] Improper neutralization of SQL parameter in MyPrestaModules - Product Catalog (CSV, Excel) Import module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,simpleimportproduct"
severity: "critical (9.8)"
---

In the module "Product Catalog (CSV, Excel) Import" (simpleimportproduct) up to version 6.7.0 from MyPrestaModules for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2024-25847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25847)
* **Published at**: 2024-02-29
* **Platform**: PrestaShop
* **Product**: simpleimportproduct
* **Impacted release**: <= 6.5.0 (6.7.1 ""fixed"" the vulnerability - See note below)
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Methods `Send::__construct()` and `importProducts::_addDataToDb` have sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

Note : The author has moved its exposed ajax script which suffers a critical issue, to the front controller under an unpredictable token. It's no longer a critical vulnerability issue, but be warned that it remains a high vulnerability issue with a CVSS 3.1 score [7.2/10](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)


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


## Patch from 6.5.0

```diff
--- 6.5.0/modules/simpleimportproduct/classes/send.php
+++ XXXXX/modules/simpleimportproduct/classes/send.php
            if (Tools::getValue('remove') == true) {
                $key = Tools::getValue('key');
                $key = pSQL($key);
-               Db::getInstance()->delete('simpleimport_tasks', "import_settings=$key");
+               Db::getInstance()->delete('simpleimport_tasks', "import_settings='".$key."'");
```

```diff
--- 6.5.0/modules/simpleimportproduct/classes/import.php
+++ XXXXX/modules/simpleimportproduct/classes/import.php
        if (Tools::getValue('id_task')) {
-           $data['id_task'] = Tools::getValue('id_task');
+           $data['id_task'] = (int) Tools::getValue('id_task');
        }
...
    if( Tools::getValue('id_task') ){
-     $data['id_task'] = Tools::getValue('id_task');
+     $data['id_task'] = (int) Tools::getValue('id_task');
    }
```




## Other recommendations

* It’s recommended to upgrade to the latest version of the module **simpleimportproduct**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-10-29 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-10-29 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-10-30 | PrestaShop Addons security Team confirms version scope |
| 2023-11-15 | Author provide a patch |
| 2024-02-22 | Received CVE ID |
| 2024-02-29 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/import-export-de-donnees/19091-catalogue-de-produits-csv-excel-dimportation.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-25847)
