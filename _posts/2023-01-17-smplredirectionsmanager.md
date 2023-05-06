---
layout: post
title: "[CVE-2023-26864] Blind SQL injection vulnerability in Redirections Manager (smplredirectionsmanager) PrestaShop module"
categories: modules
author:
- Creabilis.com
- TouchWeb.fr
- 202-ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
severity: "critical (9.8)"
---

The module Redirections Manager (smplredirectionsmanager) from Smart Plugs contains a Blind SQL injection vulnerability up to version 1.1.19.
This module is for the PrestaShop e-commerce platform.

**WARNING** : This vulnerability will bypass some WAF.

## Summary

* **CVE ID**: [CVE-2023-26864](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-26864)
* **Published at**: 2023-01-17
* **Advisory source**: none
* **Platform**: PrestaShop
* **Product**: smplredirectionsmanager
* **Impacted release**: < 1.1.19 (1.1.19 fixed the vulnerability)
* **Product author**: Smart Plugs
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `SmplTools::getMatchingRedirectionsFromParts()` hold a sensitive SQL calls that can be executed with a trivial http call and exploited to forge a blind SQL injection.

The large scope of URL exposed to the vulnerability increases its severity and the risk that a pattern of URL is in whitelist of a WAF.


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

This vulnerability permits altering the shop’s database.

## Patch of release 1.1.19

```diff
--- a/smplredirectionsmanager/classes/SmplTools.php
+++ b/smplredirectionsmanager/classes/SmplTools.php
@@ -104,10 +104,10 @@ class SmplTools
                     }
                 }
                 $contrainte_request_uri .= ($contrainte_request_uri ? ' OR' : '').' old_request_path="'.
-                    pSQL(preg_replace('#\?.*#', '', $smpl_relative_uri)).'?'.$str_querystring.'"';
+                    pSQL(preg_replace('#\?.*#', '', $smpl_relative_uri)).'?'.pSQL($str_querystring).'"';
                 foreach ($smpl_absolute_uris as $smpl_absolute_uri) {
                     $contrainte_request_uri .= ' OR old_request_path="'.
-                        pSQL(preg_replace('#\?.*#', '', $smpl_absolute_uri)).'?'.$str_querystring.'"';
+                        pSQL(preg_replace('#\?.*#', '', $smpl_absolute_uri)).'?'.pSQL($str_querystring).'"';
                 }
             }
         } else {
```

## Timeline

| Date | Action |
|--|--|
| 2022-10-10 | Issue discovered by [TouchWeb](https://www.touchweb.fr)'s auto-pentesting bots |
| 2022-10-11 | Contact the author |
| 2022-11-14 | Fix published on addons PrestaShop marketplace |
| 2023-01-12 | Request CVE ID |
| 2023-01-17 | Publish this security advisory |

## Other recommandations

* It’s recommended to upgrade to the lastest version of the module **smplredirectionsmanager**.
* Upgrade PrestaShop beyond 1.7.8.8 (and 8.0.1) to disable multiquery executions (separated by ";").
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/url-redirects/21428-redirections-manager-manage-301-302-and-404-urls.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-26864)
