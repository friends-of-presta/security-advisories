---
layout: post
title: "[CVE-2023-43980] Improper neutralization of SQL parameter in Presto Changeo - Test Site Creator module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,testsitecreator"
severity: "critical (9.8)"
---

In the module "Test Site Creator" (testsitecreator) from Presto Changeo for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-43980](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43980)
* **Published at**: 2023-09-28
* **Platform**: PrestaShop
* **Product**: testsitecreator
* **Impacted release**: <= 1.1.1 (WARNING : see WARNING below)
* **Product author**: Presto Changeo
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `TestSiteClass::TestSiteIsCreated()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : Author discontinue support of its module so you should no longer continue to use them and do not have time to confirm us the scope of impacted versions so it could impact newer versions than 1.1.1.

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
--- 1.1.1/modules/testsitecreator/classes/TestSiteClass.php
+++ XXXXX/modules/testsitecreator/classes/TestSiteClass.php
...
		return (bool)Db::getInstance()->getRow('
			SELECT * 
			FROM `'._DB_PREFIX_.'testsitecreator`
			WHERE `test_site_created` = 1
-			'.(is_null($id_testsitecreator) ? 'AND `name_testsitecreator` = "'.$name_testsitecreator.'"' : 'AND `id_testsitecreator` = '.$id_testsitecreator).'
+			'.(is_null($id_testsitecreator) ? 'AND `name_testsitecreator` = "'.pSQL($name_testsitecreator).'"' : 'AND `id_testsitecreator` = '.(int) $id_testsitecreator).'
		');
```

## Other recommendations

* Since author discontinue support on its modules, it is recommended to delete the module.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-08-02 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-08-02 | Contact Author to confirm versions scope by author |
| 2023-08-27 | Recontact Author to confirm versions scope by author |
| 2023-08-27 | Author replied us to stop communicated with him |
| 2023-09-21 | Request a CVE ID |
| 2023-09-27 | Received CVE ID |
| 2023-09-28 | Publish this security advisory |

## Links

* [Author product page](https://www.presto-changeo.com/prestashop/home/158-test-site-creator.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-43980)
