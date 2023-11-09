---
layout: post
title: "[CVE-2023-39640] Improper neutralization of SQL parameter in Cookie Law - Banner + Cookie blocker module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,cookiebanner"
severity: "critical (9.8)"
---

In the module "Cookie Law - Banner + Cookie blocker" (cookiebanner) up to version 1.5.0 from UpLight for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-39640](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39640)
* **Published at**: 2023-09-21
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: cookiebanner
* **Impacted release**: <= 1.5.0 (1.5.1 fixed the vulnerability)
* **Product author**: UpLight
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `Hook::getHookModuleExecList()` inside an override of the module has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

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

## Patch from 1.4.5 and 1.5.0

```diff
--- 1.4.5/modules/cookiebanner/controllers/front/settings.php
+++ XXXXX/modules/cookiebanner/controllers/front/settings.php
...
        } elseif (Tools::isSubmit('submitSettings')) {
            $module_list = Tools::getValue('module_list');
            $disabled_modules_list = array();
            if (is_array($module_list)) {
                foreach ($module_list as $id_module => $authorized) {
                    if (!$authorized) {
-                       $disabled_modules_list[] = $id_module;
+                       $disabled_modules_list[] = (int) $id_module;
                    }
                }
            } else {
                $this->errors[] = $this->l('No modules selected!');
            }
```

```diff
--- 1.4.5/modules/cookiebanner/override/classes/Hook.php
+++ XXXXX/modules/cookiebanner/override/classes/Hook.php
...
            if (count($disabled_modules_list)) {
-               $sql->where('m.`id_module` NOT IN ('.implode(',', $disabled_modules_list).')');
+               $sql->where('m.`id_module` NOT IN ('.implode(',', array_map('intval', $disabled_modules_list)).')');
            }
```


```diff
--- 1.5.0/modules/cookiebanner/override/classes/Hook.php
+++ XXXXX/modules/cookiebanner/override/classes/Hook.php
...
        if (!empty(self::$disabledHookModules)) {
-           $sql->where('m.id_module NOT IN (' . implode(', ', self::$disabledHookModules) . ')');
+           $sql->where('m.`id_module` NOT IN ('.implode(',', array_map('intval', self::$disabledHookModules)).')');
        }
```

**WARNING : Be warned that you must check the hook installed here** :

```diff
--- 1.4.5/override/classes/Hook.php
+++ XXXXX/override/classes/Hook.php
...
            if (count($disabled_modules_list)) {
-               $sql->where('m.`id_module` NOT IN ('.implode(',', $disabled_modules_list).')');
+               $sql->where('m.`id_module` NOT IN ('.implode(',', array_map('intval', $disabled_modules_list)).')');
            }
```

```diff
--- 1.5.0/override/classes/Hook.php
+++ XXXXX/override/classes/Hook.php
...
        if (!empty(self::$disabledHookModules)) {
-           $sql->where('m.id_module NOT IN (' . implode(', ', self::$disabledHookModules) . ')');
+           $sql->where('m.`id_module` NOT IN ('.implode(',', array_map('intval', self::$disabledHookModules)).')');
        }
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **cookiebanner**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-05-24 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-24 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-05-26 | PrestaShop Addons security Team confirm versions scope |
| 2023-07-25 | Request a CVE ID |
| 2023-08-25 | Received CVE ID |
| 2023-09-21 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/legislation/15954-cookie-law-blocage-des-cookies-banniere.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-39640)
