---
layout: post
title: "[CVE-2023-39649] Improper neutralization of SQL parameter in Theme Volty CMS Category Slider module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Vitalyn.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,theme volty,tvcmscategoryslider"
severity: "critical (9.8)"
---

In the module "Theme Volty CMS Category Slider" (tvcmscategoryslider) up to version 4.0.1 from Theme Volty for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-39649](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39649)
* **Published at**: 2023-09-26
* **Platform**: PrestaShop
* **Product**: tvcmscategoryslider
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
--- 4.0.1/tvcmscategoryslider/ajax.php
+++ 4.0.2/tvcmscategoryslider/ajax.php
        $update_position[] = 'UPDATE 
                                        `' . _DB_PREFIX_ . 'tvcmscategoryslider` 
                                    SET
-                                        `position` = ' . $pos . '
+                                        `position` = ' . (int) $pos . '
                                    WHERE
-                                        `id_tvcmscategoryslider` = ' . $value . ';';
+                                        `id_tvcmscategoryslider` = ' . (int) $value . ';';
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **tvcmscategoryslider**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
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
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-39649)
