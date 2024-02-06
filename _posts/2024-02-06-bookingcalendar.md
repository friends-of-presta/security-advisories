---
layout: post
title: "[CVE-2023-46914] Improper neutralization of SQL parameter in RM RM - Booking Calendar module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,bookingcalendar"
severity: "critical (9.8)"
---

In the module "Booking Calendar" (bookingcalendar) from RM RM for PrestaShop, a guest can perform SQL injection in affected versions if the module is not installed OR if a secret accessible to administrator is stolen.


## Summary

* **CVE ID**: [CVE-2023-46914](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-46914)
* **Published at**: 2024-02-06
* **Platform**: PrestaShop
* **Product**: bookingcalendar
* **Impacted release**: <= 2.7.9 (WARNING : Author discontinue support since years - no fix)
* **Product author**: RM RM
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

*Foreword : we are forced to tag privilege NONE on the CVSS 3.1 score which make it a critical vulnerability since it will be critical if the module has never been installed OR (if the BOOKINGCALENDAR_ics_export configuration do not exist OR is empty), but keep in mind that for the majority of installations, the gravity is reduced to [CVSS 3.1 7.2/10](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)*

The script PHP `ics_export.php` own a sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : Be warned that older versions own true criticals issues (still actively searched and exploited) and that this module is no longer maintain since years so you should delete it.

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
* Steal/Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch from 2.7.9

```diff
--- 2.7.9/modules/bookingcalendar/ics_export.php
+++ XXXXX/modules/bookingcalendar/ics_export.php
...
-if (Tools::getIsset('lang') && Configuration::get('BOOKINGCALENDAR_ics_export')==Tools::getValue('id'))
+if (Tools::getIsset('lang') && !Tools::isEmpty('id') && Tools::getValue('id') === Configuration::get('BOOKINGCALENDAR_ics_export'))
...
-	  $req.=' and idp='.Tools::getValue('id_product');
+	  $req.=' and idp='.(int) Tools::getValue('id_product');
```


```diff
--- 2.7.9/modules/bookingcalendar/bookingcalendar.php
+++ XXXXX/modules/bookingcalendar/bookingcalendar.php
...
-$row = Db::getInstance()->getRow('select ecart from `'._DB_PREFIX_.'a_booking_plus` where debut=\''.$debut.'\' and id_product=\''.$id_product.'\' ');
+$row = Db::getInstance()->getRow('select ecart from `'._DB_PREFIX_.'a_booking_plus` where debut=\''.pSQL($debut).'\' and id_product=\''.(int) $id_product.'\' ');
...
```

## Patch from 2.5.6

```diff
--- 2.5.6/modules/bookingcalendar/controllers/front/list.php
+++ XXXXX/modules/bookingcalendar/controllers/front/list.php
...
-		$enter=Tools::getValue('enter');
+		$enter=pSQL(Tools::getValue('enter'));
...
			$row = Db::getInstance()->getRow('select * from `'._DB_PREFIX_.'a_booking_plus` where id_product=\''.(int)Tools::getValue('id_product').'\' and debut=\''.Tools::getValue('enter').' 00:00:00\'');
			$row = Db::getInstance()->getRow('select * from `'._DB_PREFIX_.'a_booking_plus` where id_product=\''.(int)Tools::getValue('id_product').'\' and debut=\''.pSQL(Tools::getValue('enter')).' 00:00:00\'');
...
```


```diff
--- 2.5.6/modules/bookingcalendar/controllers/front/list1_7.php
+++ XXXXX/modules/bookingcalendar/controllers/front/list1_7.php
...
-		$enter=Tools::getValue('enter');
+		$enter=pSQL(Tools::getValue('enter'));
...
			$row = Db::getInstance()->getRow('select * from `'._DB_PREFIX_.'a_booking_plus` where id_product=\''.(int)Tools::getValue('id_product').'\' and debut=\''.Tools::getValue('enter').' 00:00:00\'');
			$row = Db::getInstance()->getRow('select * from `'._DB_PREFIX_.'a_booking_plus` where id_product=\''.(int)Tools::getValue('id_product').'\' and debut=\''.pSQL(Tools::getValue('enter')).' 00:00:00\'');
...
```

## Other recommendations

* It’s recommended to delete the module **bookingcalendar**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-10-24 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-10-24 | Contact PrestaShop Addons security Team to confirm version scope |
| 2023-10-24 | PrestaShop Addons security Team confirms version scope |
| 2024-02-05 | Received CVE ID |
| 2024-02-06 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/reservation-rental-system/24132-booking-calendar.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-46914)
