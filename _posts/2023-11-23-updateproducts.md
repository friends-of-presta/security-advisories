---
layout: post
title: "[CVE-2023-46349] Improper neutralization of SQL parameter in MyPrestaModules - Product Catalog (CSV, Excel) Export/Update module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,updateproducts"
severity: "critical (9.8)"
---

In the module "Product Catalog (CSV, Excel) Export/Update" (updateproducts) up to version 3.7.6 from MyPrestaModules for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-46349](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46349)
* **Published at**: 2023-11-23
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: updateproducts
* **Impacted release**: <= 3.7.6 (3.8.5 fixed "all" vulnerabilities known - see Note below)
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `productsUpdateModel::getExportIds()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

Note : The file which suffer of the critical problem has been partially rewriten to become an admin controller instead of an ajax script so it's not longer a critical issue since months (<= 3.7.6), only a high severity issue. Author patch all this high severity issue on the version 3.8.5, it's why we advice to upgrade to this version.

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


## Patch from 3.7.6

```diff
--- 3.7.6/modules/updateproducts/datamodel.php
+++ XXXXX/modules/updateproducts/datamodel.php
...
if( $selected_manufacturers ){
      $justProducts = false;
      $selected_manufacturers = implode(",", $selected_manufacturers);
-     $where .= " AND p.id_manufacturer IN (".pSQL($selected_manufacturers).") ";
+     $where .= " AND p.id_manufacturer IN (".implode(',', array_map('intval', explode(',', $selected_manufacturers))).") ";
    }

    if( $selected_suppliers ){
      $justProducts = false;
      $selected_suppliers = implode(",", $selected_suppliers);
-     $where .= " AND s.id_supplier IN (".pSQL($selected_suppliers).") ";
+     $where .= " AND s.id_supplier IN (".implode(',', array_map('intval', explode(',', $selected_suppliers))).") ";
    }

    if( $selected_categories ){
      $justProducts = false;
      $selected_categories = implode(",", $selected_categories);
-     $where .= " AND cp.id_category IN (".pSQL($selected_categories).") ";
+     $where .= " AND cp.id_category IN (".implode(',', array_map('intval', explode(',', $selected_categories))).") ";
    }

    if( $products_check ){
      $products_check = implode(",", $products_check);
      $justProducts = $justProducts ? 'AND' : 'OR';
-     $where .= " $justProducts p.id_product IN (".pSQL($products_check).") ";
+     $where .= " $justProducts p.id_product IN (".implode(',', array_map('intval', explode(',', $products_check))).") ";
    }
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **updateproducts**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-06-03 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-06-03 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-06-09 | PrestaShop Addons security Team confirm versions scope by author |
| 2023-08-28 | Author provide a patch which fix the remaining high severity issue |
| 2023-10-17 | Request a CVE ID |
| 2023-10-23 | Received CVE ID |
| 2023-11-23 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/data-import-export/17611-product-catalog-csv-excel-export-update.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-46349)
