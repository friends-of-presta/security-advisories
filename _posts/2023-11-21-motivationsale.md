---
layout: post
title: "[CVE-2023-46357] Improper neutralization of SQL parameter in MyPrestaModules - Cross Selling in Modal Cart module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,motivationsale"
severity: "critical (9.8)"
---

In the module "Cross Selling in Modal Cart" (motivationsale) from MyPrestaModules for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-46357](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46357)
* **Published at**: 2023-11-21
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: motivationsale
* **Impacted release**: < 3.5.0 (3.5.0 fixed the vulnerability - see note below)
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `motivationsaleDataModel::getProductsByIds()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

Note : The author has deleted from its module the files that have been suffering from critical vulnerabilities for months, BUT did not set them to be "auto-deleted" during upgrades. Therefore, there are likely merchants out there with older versions who have updated their modules, thinking they are safe. However, there is nothing safe about this, since past upgrades did not auto-delete the implicated files. To ensure everyone has a "safe version", we decided to mark all versions up to 3.5.0 as impacted by this issue.

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

## Patch from 3.2.3

```diff
--- 3.2.3/modules/motivationsale/datamodel.php
+++ XXXXX/modules/motivationsale/datamodel.php
...
  public static function getProductsByIds($product_ids)
  {
    $sql = '
			SELECT pl.name, p.*, i.id_image, pl.link_rewrite, p.reference
      FROM ' . _DB_PREFIX_ . 'product_lang as pl
      LEFT JOIN ' . _DB_PREFIX_ . 'image as i
      ON i.id_product = pl.id_product AND i.cover=1
      INNER JOIN ' . _DB_PREFIX_ . 'product as p
      ON p.id_product = pl.id_product
      WHERE pl.id_lang = ' . (int)self::$id_lang . '
      AND pl.id_shop = ' . (int)self::$id_shop . '
-     AND p.id_product IN ('.pSQL($product_ids).')
+     AND p.id_product IN ('.implode(',', array_map('intval', explode(',',$product_ids))).')
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **motivationsale**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-05-30 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-30 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-06-09 | PrestaShop Addons security Team confirms version scope |
| 2023-06-14 | Author provide a patch |
| 2023-10-17 | Request a CVE ID |
| 2023-10-23 | Received CVE ID |
| 2023-11-21 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/ventes-croisees-packs-produits/16122-cross-selling-in-modal-cart.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-46357)
