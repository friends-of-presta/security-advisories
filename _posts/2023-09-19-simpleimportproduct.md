---
layout: post
title: "[CVE-2023-39675] Improper neutralization of a SQL parameter in simpleimportproduct from MyPrestaModules module for PrestaShop"
categories: modules
author:
- sorcery.ie
meta: "CVE,PrestaShop,simpleimportproduct"
severity: "critical (9.8)"
---

In the module "SimpleImportProduct " (simpleimportproduct) for PrestaShop, an attacker can perform SQL injection.

## Summary

* **CVE ID**: [CVE-2023-39675](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39675)
* **Published at**: 2023-09-07
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: simpleimportproduct
* **Impacted release**: 
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Before 0.2.1, sensitive SQL calls in file `send.php` can be executed with a trivial http call and exploited to forge a blind SQL injection through the POST or GET submitted `key` variables.
A patch was released in august 2023.


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

* Technical and personal data leaks
* Obtain admin access
* Remove all data of the linked PrestaShop
* Display sensitive tables to front-office to unlock potential admin's ajax scripts of modules protected by token on the ecosystem


## Patch

```diff
--- a/modules/simpleimportproduct/send.php
+++ b/modules/simpleimportproduct/send.php
          $key = Tools::getValue('key');
          $key = pSQL($key);
-         Db::getInstance()->delete('simpleimport_tasks', "import_settings=$key");
+         Db::getInstance()->delete('simpleimport_tasks', "import_settings='".$key."'");
```


## Other recommendations

* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.



## Timeline

| Date | Action |
|--|--|
| 2023-07-10 |  Vulnerability found during an audit by sorcery.ie |
| 2023-08-28 | CVE-2023-39675 assigned |
| 2023-09-07 | Blog post released by [sorcery.ie](https://blog.sorcery.ie/posts/simpleimportproduct_sqli/)|


## Links

* [Blog post](https://blog.sorcery.ie/posts/simpleimportproduct_sqli/)
* [Author page](https://myprestamodules.com/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-39675)

