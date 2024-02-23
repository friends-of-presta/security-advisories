---
layout: post
title: "[CVE-2023-45379] Improper neutralization of SQL parameter in Posthemes Rotator Img module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,posthemes,posrotatorimg"
severity: "critical (9.8)"
---

In the module "Rotator Img" (posrotatorimg) in versions at least up to 1.1 from PosThemes for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-45379](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45379)
* **Published at**: 2023-10-17
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: posrotatorimg
* **Impacted release**: <= 1.1 (Author never confirm fix)
* **Product author**: PosThemes
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description


The script `ajax.php` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards.

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

## Patch from 1.1

```diff
--- 1.1/modules/posrotatorimg/ajax.php
+++ XXX/modules/posrotatorimg/ajax.php
        $params = $_POST; 

-       $id_product = $params['id_product'];
+       $id_product = (int) $params['id_product'];
        $action = $params['action'];
...
        $images= Image::getImages((int)Context::getContext()->language->id,$id_product);
-       $id = $params['img_id']; 
+       $id = (int) $params['img_id']; 
```

Be warned that there is other sensitives SQL calls inside this module accessible to administrators. Since there is thousand of injection SQL accessible to administrators on the PrestaShop's ecosystem, these vulnerabilities are ignored until author provide a patch.


## Other recommendations

* It’s recommended to apply patch given or delete the module (NB : disabled it is useless)
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-04-28 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-04-28 | Contact Author to confirm versions scope |
| 2023-04-28 | Request a CVE ID |
| 2023-06-05 | Relaunch author to confirm versions scope |
| 2023-10-11 | Received CVE ID |
| 2023-10-17 | Publish this security advisory |


## Links

* [Posthemes product page on Themes Forest](https://themeforest.net/user/posthemes/portfolio)
* [Posthemes website](https://posthemes.com/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45379)

