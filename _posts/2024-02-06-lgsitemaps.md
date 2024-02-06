---
layout: post
title: "[CVE-2024-24311] Improper Limitation of a Pathname to a Restricted Directory in Linea Grafica - Multilingual and Multistore Sitemap Pro – SEO module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,lgsitemaps"
severity: "high (7.5), GDPR violation"
---

In the module "Multilingual and Multistore Sitemap Pro – SEO" (lgsitemaps) from Linea Grafica for PrestaShop, a guest can download personal information without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2024-24311](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24311)
* **Published at**: 2024-02-06
* **Platform**: PrestaShop
* **Product**: lgsitemaps
* **Impacted release**: <= 1.6.5 (1.6.6 fixed the vulnerability)
* **Product author**: Linea Grafica
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5)

## Description

Due to a lack of permissions control and a lack of control in the path name construction, a guest can perform a path traversal to view all XML files on the affected PrestaShop.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: none
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

## Possible malicious usage

* Stealing all XML files from the PrestaShop including those under .htaccess/WAF restriction (like config.xml in modules root)

## Patch from 1.6.5

```diff
--- 1.6.5/modules/lgsitemaps/controllers/front/sitemap.php
+++ 1.6.6/modules/lgsitemaps/controllers/front/sitemap.php
...
        if (!Tools::getIsset('cron')) {
            $name = Tools::getValue('name');
+	    $name = str_replace('config', '', basename(Tools::getValue('name')));
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **lgsitemaps**.

## Timeline

| Date | Action |
|--|--|
| 2023-07-23 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-07-23 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-08-22 | PrestaShop Addons security Team confirm versions scope by author |
| 2023-09-04 | Author provide a patch |
| 2024-02-05 | Received CVE ID |
| 2024-02-06 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/seo-natural-search-engine-optimization/7507-multilingual-and-multistore-sitemap-pro-seo.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-24311)
