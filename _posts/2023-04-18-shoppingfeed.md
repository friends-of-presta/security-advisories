---
layout: post
title: "[CVE-2023-28839] Improper neutralization of a SQL parameter in Shoppingfeed module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,shoppingfeed"
severity: "critical (9.8)"
---

SQL injection vulnerability found in the module "Shoppingfeed PrestaShop Plugin (Feed&Order)" (aka shoppingfeed) for PrestaShop from 1.4.0 to 1.8.2. (1.8.3 fix the issue) allow a remote attacker to gain privileges.

## Summary

* **CVE ID**: [CVE-2023-28839](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28839)
* **Published at**: 2023-04-18
* **Advisory source**: [Github repository of Shoppingfeed PrestaShop Plugin](https://github.com/shoppingflux/module-prestashop/security/advisories/GHSA-vfmq-w777-qvcf)
* **Platform**: Shoppingfeed
* **Product**: shoppingfeed
* **Impacted release**: from 1.4.0 to 1.8.2 (1.8.3 fix the issue).
* **Product author**: 202 ecommerce
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

From 1.4.0 to 1.8.2 (1.8.3 fix the issue), a sensitive SQL call in `ShoppingfeedToken::findByToken()` can be executed with a trivial http call and exploited to forge a blind SQL injection through the POST or GET submitted variable `token`.

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
* Display sensitives tables to front-office to unlock potential admin’s ajax scripts of modules protected by token on the ecosystem

## Patch

```diff
--- a/modules/shoppingfeed/classes/ShoppingfeedToken.php
+++ b/modules/shoppingfeed/classes/ShoppingfeedToken.php
@@ -138,7 +138,7 @@ public function findByToken($token)
         $query = (new DbQuery())
             ->select('*')
             ->from(self::$definition['table'])
-            ->where("content = '$token'")
+            ->where('content = "' . pSQL($token) . '"')
         ;
 
         return Db::getInstance(_PS_USE_SQL_SLAVE_)->getRow($query);
```

[See also](https://github.com/shoppingflux/module-prestashop/pull/209/files)


## Other recommendations

* It’s recommended to upgrade the module beyond 1.8.3.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix ps_ by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942’s rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-10-14 | Wargan Solutions discover the vulnerability during an audit ordered by Shoppingfeed and 202 ecommerce |
| 2022-10-14 | Publish the patch release 1.8.3 |
| 2022-10-18 | Shoppingfeed send a first newsletter to invite all merchands to upgrade up to 1.9.0 |
| 2022-12-12 | Shoppingfeed send a second reminder to invite all merchands to upgrade |
| 2022-03-28 | Shoppingfeed send a third reminder to invite all merchands to upgrade up to 1.9.3 |
| 2023-04-18 | Publish this security advisory |

## Links

* [Github repository](https://github.com/shoppingflux/module-prestashop/security/advisories/GHSA-vfmq-w777-qvcf)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-28839)

