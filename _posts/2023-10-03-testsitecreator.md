---
layout: post
title: "[CVE-2023-43981] Deserialization of Untrusted Data in Presto Changeo - Test Site Creator module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,testsitecreator"
severity: "critical (10)"
---

In the module "Test Site Creator" (testsitecreator) from Presto Changeo for PrestaShop, a guest can execute a remote code via an untrusted data deserialized.


## Summary

* **CVE ID**: [CVE-2023-43981](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43981)
* **Published at**: 2023-10-03
* **Platform**: PrestaShop
* **Product**: testsitecreator
* **Impacted release**: <= 1.1.1 (WARNING : see WARNING below)
* **Product author**: Presto Changeo
* **Weakness**: [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
* **Severity**: critical (10)

## Description

A deserialization of untrusted data in scripts delete_excluded_folder.php and verify_excluded_folder.php can be used with a trivial http call and exploited to execute a remote code.

**WARNING** : Author discontinue support of its module so you should no longer continue to use them and do not have time to confirm us the scope of impacted versions so it could impact newer versions than 1.1.1.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: changed
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Steal/Remove data from the associated PrestaShop

## Patch from 1.1.1

```diff
--- 1.1.1/modules/testsitecreator/lib/verify_excluded_folder.php
+++ XXXXX/modules/testsitecreator/lib/verify_excluded_folder.php
...
-	$tsc_excluded_folders = unserialize(Tools::getValue('tsc_excluded_folders'));
+	$tsc_excluded_folders = unserialize(Tools::getValue('tsc_excluded_folders'), ['allowed_classes' => false]);
```

```diff
--- 1.1.1/modules/testsitecreator/lib/delete_excluded_folder.php
+++ XXXXX/modules/testsitecreator/lib/delete_excluded_folder.php
...
-	$tsc_excluded_folders = unserialize(Tools::getValue('tsc_excluded_folders'));
+	$tsc_excluded_folders = unserialize(Tools::getValue('tsc_excluded_folders'), ['allowed_classes' => false]);
```

## Other recommendations

* Since author discontinue support on its modules, it is recommended to delete the module.
* Activate OWASP 933's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-08-10 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-08-10 | Contact Author to confirm versions scope by author |
| 2023-08-27 | Recontact Author to confirm versions scope by author |
| 2023-08-27 | Author replied us to stop communicating with him |
| 2023-09-21 | Request a CVE ID |
| 2023-09-27 | Received CVE ID |
| 2023-10-03 | Publish this security advisory |

## Links

* [Author product page](https://www.presto-changeo.com/prestashop/home/158-test-site-creator.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-43981)
