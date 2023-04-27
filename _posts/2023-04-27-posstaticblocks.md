---
layout: post
title: "[CVE-2023-30189] Improper neutralization of SQL parameter in Posthemes Static Blocks module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,posstaticblocks"
severity: "critical (9.8)"
---

In the module "Posthemes Static Blocks" (posstaticblocks), a guest can perform SQL injection in affected versions.

Note : if ajax.php do not exist in the root module directory, you are not concerned.

## Summary

* **CVE ID**: [CVE-2023-30189](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30189)
* **Published at**: 2023-04-27
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: posthemes
* **Impacted release**: <= 1.0 (1.0.0 seems not concerned - no semver versionning)
* **Product author**: posstaticblocks
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description


The method `posstaticblocks::getPosCurrentHook()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

The exploit can be used even if the module is not activated.

**WARNING** : This exploit is actively used to deploy webskimmer to massively stole credit cards.


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
* Copy/past datas from sensibles tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijacked emails


## Proof of concept


```bash
curl -v -X POST -d 'module_id=1%22;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--' 'https://preprod.XX/modules/posstaticblocks/ajax.php'
```

## Patch from 1.0

Version A seen : 

```diff
--- 1.0A/modules/posstaticblocks/posstaticblocks.php
+++ XXXX/modules/posstaticblocks/posstaticblocks.php
...
-$sql = 'SELECT psb.`hook_module` FROM '._DB_PREFIX_.'pos_staticblock AS psb LEFT JOIN '._DB_PREFIX_.'pos_staticblock_shop AS pss ON psb.`id_posstaticblock`= pss.`id_posstaticblock` WHERE  psb.`name_module` ="'.$name_module.'" AND pss.`id_shop` = "'.$id_shop.'"';
+$sql = 'SELECT psb.`hook_module` FROM '._DB_PREFIX_.'pos_staticblock AS psb LEFT JOIN '._DB_PREFIX_.'pos_staticblock_shop AS pss ON psb.`id_posstaticblock`= pss.`id_posstaticblock` WHERE  psb.`name_module` ="'.pSQL($name_module).'" AND pss.`id_shop` = "'.(int)$id_shop.'"';
```

Version B seen : 

```diff
--- 1.0B/modules/posstaticblocks/posstaticblocks.php
+++ XXXX/modules/posstaticblocks/posstaticblocks.php
...
-WHERE m.`id_module` = ' . $id_module);
+WHERE m.`id_module` = ' . (int) $id_module);
```

Be warn that there is other sensitives SQL calls inside this module accessible to administrators. Since there is thousand of injection SQL accessible to administrators on the Prestashop's ecosystem, these vulnerabilities are ignored until author provide a patch.

## Other recommandations

* It’s recommended to apply patch given or delete the module (NB : disabled it is useless)
* Upgrade PrestaShop beyond 1.7.8.8 (and 8.0.1) to disable multiquery executions (separated by ";").
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-03-12 | Issue discovered during a code review by TouchWeb.fr |
| 2023-03-21 | Contact Author to confirm versions scope |
| 2023-03-21 | A member of Friends of Presta (FX) provide another version which need a new patch |
| 2023-03-25 | Request a CVE ID |
| 2023-04-27 | Author never answer and exploit is used to massively stole credit cards |
| 2023-04-27 | Publication of this security advisory without delay due to emergency |

## Links

* [Posthemes product page on Themes Forest](https://themeforest.net/user/posthemes/portfolio)
* [Posthemes website](https://posthemes.com/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/name=CVE-2023-30189)

