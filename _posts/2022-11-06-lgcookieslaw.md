---
layout: post
title: "[CVE-2022-44727] Blind SQL injection vulnerability in PrestaShop lgcookieslaw module"
categories: modules
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
severity: "critical (9.8)"
---


The PrestaShop e-commerce platform module EU Cookie Law GDPR (Banner + Blocker) contains a Blind SQL injection vulnerability up to version 2.1.2. This module is widely deployed and is a “Best seller” on the add-ons store.


## Summary

* **CVE ID**: CVE-2022-44727
* **Published at**: 2022-11-06
* **Advisory source**: [securityandstuff.com](https://securityandstuff.com/posts/cve-2022-44727/)
* **Platform**: PrestaShop
* **Product**: lgcookieslaw
* **Impacted release**: >= 1.5.0, < 2.1.3 (2.1.3 fixed the vulnerability)
* **Product author**: Línea Gráfica
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The EU Cookie Law GDPR (Banner + Blocker) module before 2.1.3 for PrestaShop allows SQL Injection via a cookie ( lgcookieslaw or __lglaw ). 


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Possible malicious usage

This vulnerability permits reading the shop’s database, allowing access to PII, and installing malware such as credit card stealers.

The vulnerability lies in a cookie used by the module to store the user’s choices.

## Proof of concept

### Version 2

For newer versions of the module, the cookie lgcookieslaw contains a Base64 encoded JSON object instead of CSV.

To exploit these versions, you’ll need to modify the lgcookieslaw_accepted_purposes of the object and then reencode to Base64:

`"lgcookieslaw_accepted_purposes":"[\"1\",\"2\",\"3\",\"4\",\"5 AND SLEEP(5)"]"`

### Version 1

For older versions set the `__lglaw cookie to 1,2,3,4) AND SLEEP(5)--`.


## Patch of release 2.4.3

### Version 2

```diff
--- 2.x.x-/lgcookieslaw/classes/LGCookiesLawPurpose.php
+++ 2.1.3/lgcookieslaw/classes/LGCookiesLawPurpose.php
    public static function getLockedModules($enabled_purposes = null, $id_shop = null, $active = true)
    {
        $context = Context::getContext();

        if (is_null($id_shop)) {
            $id_shop = $context->shop->id;
        }

        $query = new DbQuery();

        $query->select('a.`' . self::$definition['primary'] . '`, a.`locked_modules`');
        $query->from(self::$definition['table'], 'a');
        $query->where('a.`id_shop` = ' . (int)$id_shop);

        if (!is_null($enabled_purposes)) {
+           $enabled_purposes = implode(', ', array_map('intval', explode(',', $enabled_purposes)));
            $query->where('a.`' . self::$definition['primary'] .'` NOT IN (' . pSQL($enabled_purposes) . ')');
        }

        if ($active) {
            $query->where('a.`active` = ' . (int)$active);
        }

        return Db::getInstance()->executeS($query);
    }
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **lgcookieslaw**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/legal/8734-eu-cookie-law-gdpr-banner-blocker.html)
* [National Vulerability Database](https://nvd.nist.gov/vuln/detail/CVE-2022-44727)
