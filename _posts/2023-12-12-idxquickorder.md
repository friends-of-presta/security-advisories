---
layout: post
title: "[CVE-2023-46989] Improper neutralization of SQL parameter in Innovadeluxe - Quick Order module for PrestaShop"
categories: modules
author:
- Creabilis.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,idxquickorder"
severity: "critical (9.8)"
---

In the module "Quick Order" (idxquickorder) all versions below 1.4.0 from Innovadeluxe for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-46989](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46989)
* **Published at**: 2023-12-12
* **Platform**: PrestaShop
* **Product**: idxquickorder
* **Impacted release**: <1.4.0 (1.4.0 fixed the vulnerability)
* **Product author**: Innovadeluxe
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `IdxquickorderProductListModuleFrontController::getProducts()` in controllers/front/productlist.php has a sensitive SQL call that can be executed with a trivial http call and exploited to forge an SQL injection.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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

## Patch from 1.1.1

```diff
--- 1.1.1/modules/idxquickorder/controllers/front/productlist.php
+++ XXXXX/modules/idxquickorder/controllers/front/productlist.php
...
        if(Tools::getValue('limitini')) {
-         $limit_ini = Tools::getValue('limitini');
+         $limit_ini = (int) Tools::getValue('limitini');
        } else {
            $limit_ini = null;
        }
        if(Tools::getValue('limitend')) {
-           $limit_end = Tools::getValue('limitend');
+           $limit_end = (int) Tools::getValue('limitend');
        } else {
             $limit_end = null;   
        }
        if($limit_ini || $limit_end) {        
-           $this->ajaxProcessProductlist($limit_ini, $limit_end, Tools::getValue('catid'));
+           $this->ajaxProcessProductlist($limit_ini, $limit_end, (int) Tools::getValue('catid'));
...
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **idxquickorder**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-10-27 | Issue discovered during a code review by [Creabilis](https://www.creabilis.com) |
| 2023-10-27 | Contact PrestaShop Addons security Team to confirm version scope by author  |
| 2023-10-27 | PrestaShop Addons security Team confirms version scope by author  |
| 2023-10-27 | Request a CVE ID |
| 2023-11-06 | Received CVE ID |
| 2023-12-12 | Publication of this advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/blog-forum-actualites/4731-idxquickorder-un-blog-professionnel-pour-votre-boutique.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-46989)
