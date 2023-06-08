---
layout: post
title: "[CVE-2023-27032] Improper neutralization of SQL parameter in Idnovate - AdvancedPopupCreator module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- Ambris Informatique
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,advancedpopupcreator"
severity: "critical (9.8)"
---

In the module "Advanced Popup Creator" (advancedpopupcreator) from Idnovate for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-27032](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27032)
* **Published at**: 2023-04-11
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: advancedpopupcreator
* **Impacted release**: <= 1.1.24 (1.1.25 fixed the vulnerability)
* **Product author**: Idnovate
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `AdvancedPopup::getPopups()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : Can be easily detected by blind sql injection pentest, so blackhats already know it - and will certainly bypass some WAF. For this reason, POC is not given as usual.

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
* Remove data on the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijacked emails

## Patch from 1.1.24

```diff
1.1.24/advancedpopupcreator/classes/AdvancedPopup.php

--- 1.1.24/advancedpopupcreator/classes/AdvancedPopup.php
+++ 1.1.25/advancedpopupcreator/classes/AdvancedPopup.php
@@ -273,7 +273,7 @@ class AdvancedPopup extends ObjectModel
                 OR FIND_IN_SET("'.Tools::getRemoteAddr().'", `display_ip_string`))
             AND (`display_url_string` = ""
                 OR `display_url_string` IS NULL
-                OR INSTR("'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'].'", `display_url_string`) > 0)
+                OR INSTR("'.pSQL($_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']).'", `display_url_string`) > 0)
             ';

         if ((int)$this->context->customer->id_gender) {
@@ -584,6 +584,8 @@ class AdvancedPopup extends ObjectModel
             $zone = Country::getIdZone($this->context->country->id);
         }

+        $availablePopups = (strpos($availablePopups, ',') !== false ? implode(',', array_map('intval', explode(',', $availablePopups))) : (int) $availablePopups);
+
         $query = 'SELECT *
             FROM `'._DB_PREFIX_.$this->def['table'].'`
             INNER JOIN `'. _DB_PREFIX_.$this->def['table'].'_lang` ON `'._DB_PREFIX_.$this->def['table'].'`.`id_advancedpopup` = `'._DB_PREFIX_.$this->def['table']. '_lang`.`id_advancedpopup`


```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **advancedpopupcreator**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-02-17 | Issue discovered during a security audit by [TouchWeb](https://www.touchweb.fr) |
| 2023-02-17 | Contact Addons security Team |
| 2022-02-17 | Fix published within 4 hours by author on addons PrestaShop marketplace |
| 2023-02-17 | Request CVE ID |
| 2023-04-06 | Publication of the security advisory without delay since exploit can be too easily seen |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/pop-up/23773-popup-on-entry-exit-popup-add-product-and-newsletter.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-27032)
