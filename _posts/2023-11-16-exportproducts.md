---
layout: post
title: "[CVE-2023-45387] Improper neutralization of SQL parameter in MyPrestaModules - Product Catalog (CSV, Excel, XML) Export PRO module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,exportproducts"
severity: "critical (9.8)"
---

In the module "Product Catalog (CSV, Excel, XML) Export PRO" (exportproducts) in versions up to 5.0.0 from MyPrestaModules for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-45387](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45387)
* **Published at**: 2023-11-16
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: exportproducts
* **Impacted release**: <= 5.0.0 (considered to be "truly" fixed on 5.1.0 - see note below)
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `exportProduct::_addDataToDb()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

Note : The author has deleted from its module the file that have been suffering from this leak for months, BUT did not set it to be "auto-deleted" during upgrades. Therefore, there are likely merchants out there with older versions who have updated their modules thinking they are safe. However, there is nothing safe about this since past upgrades do not auto-delete the implicated file. To ensure everyone has a "safe version", we decided to mark all versions up to 2.1.02 as impacted by this issue.

**WARNING** : be warned that an old critical vulnerability is consistently being exploited in this module. If you have exportproducts-ajax.php in the root folder, it is strongly recommended to upgrade immediately.

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

## Patch from 4.1.1

This file has been deleted in newer versions, you should upgrade instead of patch since there is other sensitive problems with these old versions.

```diff
--- 4.1.1/modules/exportproducts/export.php
+++ XXXXX/modules/exportproducts/export.php
...
      if( Tools::getValue('id_task') ){
-       $data['id_task'] = Tools::getValue('id_task');
+       $data['id_task'] = pSQL(Tools::getValue('id_task'));
      }
      else{
        $data['id_task'] = 0;
      }

      // Db::getInstance(_PS_USE_SQL_SLAVE_)->insert('exportproducts_data', $data);

      $this->_insertValues .= '("'.$data['row'].'","'.$data['field'].'","'.$data['value'].'","'.$data['id_task'].'"),';
```

## Other recommendations

* You should consider restricting the access of modules/exportproducts/upload/ to a whitelist
* It’s recommended to upgrade to the latest version of the module **exportproducts**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-05-28 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-28 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-06-09 | PrestaShop Addons confirms versions scopes |
| 2023-06-14 | Author provide patch |
| 2023-10-08 | Request a CVE ID |
| 2023-10-12 | Received CVE ID |
| 2023-11-16 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/data-import-export/18662-product-catalog-csv-excel-xml-export-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45387)
