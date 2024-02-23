---
layout: post
title: "[CVE-2023-39651] Improper neutralization of SQL parameter in Theme Volty CMS BrandList module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Vitalyn.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,theme volty,tvcmsbrandlist"
severity: "critical (9.8)"
---

In the module "Theme Volty CMS BrandList" (tvcmsbrandlist) up to version 4.0.1 from Theme Volty for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-39651](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39651)
* **Published at**: 2023-09-26
* **Platform**: PrestaShop
* **Product**: tvcmsbrandlist
* **Impacted release**: <= 4.0.1 (4.0.2 fixed the vulnerability)
* **Product author**: Theme Volty
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The script ajax.php has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

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

## Patch from 4.0.1

```diff
--- 4.0.1/tvcmsbrandlist/ajax.php
+++ 4.0.2/tvcmsbrandlist/ajax.php
        $update_position[] = 'UPDATE 
                                        `' . _DB_PREFIX_ . 'tvcmsbrandlist` 
                                    SET
-                                        `position` = ' . $pos . '
+                                        `position` = ' . (int) $pos . '
                                    WHERE
-                                        `id_tvcmsbrandlist` = ' . $value . ';';
+                                        `id_tvcmsbrandlist` = ' . (int) $value . ';';
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **tvcmsbrandlist**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-02-10 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-02-10 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-02-15 | Author provide a patch which still own all criticals vulnerabilities |
| 2023-04-13 | Recontact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-04-13 | Request a CVE ID |
| 2023-05-19 | Author provide patch |
| 2023-08-15 | Received CVE ID |
| 2023-09-26 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/themes-electronique-high-tech/29992-electron-mega-electronique-high-tech-store.html)
* [Author product page](https://themevolty.com/electron-mega-electronic-store)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-39651)
