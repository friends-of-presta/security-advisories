---
layout: post
title: "[CVE-2023-45381] Improper neutralization of SQL parameter in WebshopWorks Creative Popup module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,creativepopup"
severity: "critical (9.8)"
---

In the module "Creative Popup" (creativepopup) up to version 1.6.9 from WebshopWorks for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-45381](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45381)
* **Published at**: 2023-10-19
* **Platform**: PrestaShop
* **Product**: creativepopup
* **Impacted release**: <=  1.6.9 (1.6.10 fixed the vulnerability)
* **Product author**: WebshopWorks
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The function `cp_download_popup()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : Be warned that this exploit will bypass some WAF.

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

## Patch from 1.6.9

```diff
--- 1.6.9/modules/creativepopup/helper.php
+++ XXXXX/modules/creativepopup/helper.php
...
$import = new CpImportUtil($destination);
            try {
                method_exists('Tools', 'deleteFile') ? Tools::deleteFile($destination) : unlink($destination);
            } catch (Exception $ex) {
                // TODO
            }
            // rename imported popup
            $title = !empty(${'_COOKIE'}['cpNewTitle']) ? ${'_COOKIE'}['cpNewTitle'] : 'Unnamed';
            setcookie('cpNewTitle', '', 1);
-           Db::getInstance()->update('creativepopup', array('name' => $title), 'id = '.$import->lastImportId);
+           Db::getInstance()->update('creativepopup', array('name' => pSQL($title)), 'id = '.$import->lastImportId);
            // redirect after import

```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **creativepopup**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-05-04 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-04 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-05-04 | PrestaShop Addons security Team confirm versions scope |
| 2023-05-19 | Request a CVE ID |
| 2023-10-11 | Received CVE ID |
| 2023-10-19 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/pop-up/39348-creative-popup.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45381)
