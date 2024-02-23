---
layout: post
title: "[CVE-2023-45376] Improper neutralization of SQL parameter in HiPresta - Carousels Pack - Instagram, Products, Brands, Supplier module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,hicarouselspack"
severity: "critical (9.8)"
---

In the module "Carousels Pack - Instagram, Products, Brands, Supplier" (hicarouselspack) up to version 1.5.0 from HiPresta for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-45376]
* **Published at**: 2023-10-19
* **Platform**: PrestaShop
* **Product**: hicarouselspack
* **Impacted release**: <= 1.5.0 (1.5.1 fixed the vulnerability)
* **Product author**: HiPresta
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `HiCpProductGetter::getViewedProduct()` has sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : Be warned that this exploit will certainly bypass some WAF. For this reason, POC is not given as usual.

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


## Patch from 1.5.0

```diff
--- 1.5.0/modules/hicarouselspack/hicarouselspack.php
+++ 1.5.1/modules/hicarouselspack/hicarouselspack.php
...
public function hookDisplayHeader()
    {
-       $this->addNewViewedProductId(Tools::getValue('id_product'));
+       $this->addNewViewedProductId((int) Tools::getValue('id_product'));

```

```diff
--- 1.5.0/modules/hicarouselspack/classes/HiProductGetter.php
+++ 1.5.1/modules/hicarouselspack/classes/HiProductGetter.php
...
    public function getViewedProduct($viewed_ids, $limit, $out_of_stock = false)
    {
        if ($viewed_ids == '') {
            return false;
        }
        $ids = array_unique(explode(',', $viewed_ids));
        $sql = '
            SELECT DISTINCT p.id_product, stock.out_of_stock, IFNULL(stock.quantity, 0) as quantity 
            FROM '._DB_PREFIX_.'product p
            '.Product::sqlStock('p', 0).'
-           WHERE p.`id_product` IN ('.pSQL(implode(',', $ids)).')';
+           WHERE p.`id_product` IN ('.implode(',', array_map('intval', $ids)).')';

```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **hicarouselspack**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-01-12 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-01-13 | FOP Security team contact Addons security Team |
| 2023-01-13 | Author provide a patch which was incomplete |
| 2023-05-19 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-05-19 | Request a CVE ID |
| 2023-08-22 | PrestaShop Addons security Team confirm versions scope by author |
| 2023-09-05 | Author provide a complete patch |
| 2023-10-11 | Received CVE ID |
| 2023-10-19 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/sliders-galleries/20410-carousels-pack-instagram-products-brands-supplier.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45376)
