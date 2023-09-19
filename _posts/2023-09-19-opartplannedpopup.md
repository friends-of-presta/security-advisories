---
layout: post
title: "[CVE-2023-34577] Improper neutralization of SQL parameter in Opart Planned popup for PrestaShop"
categories: modules
author:
- Opart
- TouchWeb.fr
- Creabilis.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,opartplannedpopup"
severity: "critical (9.8)"
---

In the module "Opart planned popup" (opartplannedpopup) up to version 1.4.11 from Opart for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-34577](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34577)
* **Published at**: 2023-09-19
* **Platform**: PrestaShop
* **Product**: opartplannedpopup
* **Impacted release**: <= 1.4.11 (1.4.12 fixed the vulnerability)  
* **Product author**: Opart
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Methods `OpartPlannedPopupModuleFrontController::prepareHook()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

This exploit uses a PrestaShop specific controller and most attackers can conceal this controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.


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


## Patch from 1.4.11

```diff
--- 1.4.11/modules/opartplannedpopup/opartplannedpopup.php
+++ 1.4.12/modules/opartplannedpopup/opartplannedpopup.php
...
private function prepareHook()
	{
		$where = '';

		if (get_class($this->context->controller) == 'OrderController')
		{
            if (Tools::getIsset('step')) {
                $current_step = Tools::getValue('step');
            } else {
                $current_step = 0;
            }
-			$where = 'p.display_order="" OR (p.display_order LIKE "'.$current_step.'" OR ';
+			$where = 'p.display_order="" OR (p.display_order LIKE "'.(int)$current_step.'" OR ';
-			$where .= 'p.display_order LIKE "'.$current_step.',%" OR p.display_order LIKE "%,'.$current_step.',%" OR ';
+			$where .= 'p.display_order LIKE "'.(int)$current_step.',%" OR p.display_order LIKE "%,'.(int)$current_step.',%" OR ';
-			$where .= 'p.display_order LIKE "%,'.$current_step.'")';
+			$where .= 'p.display_order LIKE "%,'.(int)$current_step.'")';
		}
```

## Other recommandations

* It’s recommended to upgrade to the latest version of the module **opartplannedpopup**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skilled because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-10-04 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr/) |
| 2022-10-04 | Contact Author to confirm version scope |
| 2022-10-04 | Author confirm versions scope |
| 2023-05-24 | Request CVE ID |
| 2023-09-05 | Received CVE ID |
| 2023-09-19 | Publish this security advisory |

Opart thanks [TouchWeb.fr](https://www.touchweb.fr/) and [Creabilis.com](https://www.creabilis.com/) for their courtesies and their help after the vulnerability disclosure.

## Links

* [Author product page](https://www.store-opart.fr/p/16-op-art-planned-popup.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-34577)
