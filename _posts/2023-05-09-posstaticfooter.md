---
layout: post
title: "[CVE-2023-30194] Improper neutralization of SQL parameter in Posthemes - Static Footer module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,posstaticfooter"
severity: "critical (9.8)"
---

In the module "Static Footer" (posstaticfooter) from PosThemes for PrestaShop, a guest can perform SQL injection in affected versions.

Note : if ajax.php do not exist in the root module directory, you are not concerned.

## Summary

* **CVE ID**: [CVE-2023-30194](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30194)
* **Published at**: 2023-05-09
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: posstaticfooter
* **Impacted release**: <= 1.0 (1.0.0 seems not concerned - no semver versionning)
* **Product author**: posthemes
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `posstaticfooter::getPosCurrentHook()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

The exploit can be used even if the module is not activated.

**WARNING** : This exploit is actively used to deploy webskimmer to massively steal credit cards.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails


## Proof of concept


```bash
curl -v -X POST -d 'module_id=1%22;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--' 'https://preprod.XX/modules/posstaticfooter/ajax.php'
```

## Patch from 1.0

Version A seen : 

```diff
--- 1.0A/modules/posstaticfooter/posstaticfooter.php
+++ XXXX/modules/posstaticfooter/posstaticfooter.php
...
-$sql = 'SELECT psb.`hook_module` FROM '._DB_PREFIX_.'pos_staticfooter AS psb LEFT JOIN '._DB_PREFIX_.'pos_staticfooter_shop AS pss ON psb.`id_posstaticblock`= pss.`id_posstaticblock` WHERE  psb.`name_module` ="'.$name_module.'" AND pss.`id_shop` = "'.$id_shop.'"';
+$sql = 'SELECT psb.`hook_module` FROM '._DB_PREFIX_.'pos_staticfooter AS psb LEFT JOIN '._DB_PREFIX_.'pos_staticfooter_shop AS pss ON psb.`id_posstaticblock`= pss.`id_posstaticblock` WHERE  psb.`name_module` ="'.pSQL($name_module).'" AND pss.`id_shop` = "'.$id_shop.'"';
```

Version B seen : 

```diff
--- 1.0B/modules/posstaticfooter/posstaticfooter.php
+++ XXXX/modules/posstaticfooter/posstaticfooter.php
...
-WHERE m.`id_module` = ' . $id_module);
+WHERE m.`id_module` = ' . (int) $id_module);
```

Be warn that there is other sensitives SQL calls inside this module accessible to administrators. Since there is thousand of injection SQL accessible to administrators on the PrestaShop's ecosystem, these vulnerabilities are ignored until author provide a patch.


## Other recommendations

* It’s recommended to apply patch given or delete the module (NB : disabled it is useless)
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-03-12 |Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-03-21 | Contact Author to confirm versions scope |
| 2023-03-21 | A member of Friends of Presta (FX) provide another version which need a new patch |
| 2023-05-09 | Author never answer and exploit is used to massively stole credit cards |
| 2023-05-09 | Publication of this security advisory without delay due to emergency |

## Links

* [Posthemes product page on Themes Forest](https://themeforest.net/user/posthemes/portfolio)
* [Posthemes website](https://posthemes.com/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-30194)

