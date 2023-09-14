# security-advisories

## Api and feed

You can access the data from:
 - [the search api](https://security.friendsofpresta.org/search.json)
 - [the rss feed](https://security.friendsofpresta.org/feed.xml)

## How to publish or update a new advisory

1. If the vulnerability is NOT already public, please contact security/at/friendsofpresta.org
2. Fork this repository
3. Create a new file in _post sub directory with the nomenclature YYYY-MM-DD-explicit-short-name.md

Sample header of an advisory file.
```MD
---
layout: post #DO NOT CHANGE "post"
title: "[CVE-YYYY-XXXXX] The type and short title vulnerability"
categories: module
author:
- Friends-Of-Presta.org
meta: "module,PrestaShop"
severity: "high (8.1)"
---
```
Instructions:
* layout: DO NOT CHANGE "post"
* title: Choose an explicit title with the type of exploit and the application (module name, ...)
* categories: Choose one of modules|core|dependancies
* author: by default "Friends-Of-Presta.org" and credit the discoverer of the vulnerability, the one who exchange with the author of the module and the editor who document this advisory
* meta: Not mandatory
* severity: CVSS values

Sample body of an advisory file.
```MD

Excerpt of the advisory

## Summary

* **CVE ID**: CVE-YYYY-XXXXXX (or "pending" if submitted or "none" if not )
* **Published at**: YYYY-MM-DD
* **Advisory source**: [related post](https://related_URL/)
* **Platform**: PrestaShop
* **Product**: module directory
* **Impacted release**: >= 1.5.0, < 2.1.3 (2.1.3 fixed the vulnerability)
* **Product author**: Author of the product
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html) (Common weakness enumerator (CWE) > refer to https://cwe.mitre.org/data/definitions/1387.html)
* **Severity**: critical (9.4) // based on CVSS base metrics

## Description

The technical description of the vulnerability

## CVSS base metrics

// refer to this description > https://www.first.org/cvss/v3.1/user-guide

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: low

**Vector string**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L

## Possible malicious usage

// Explain what's can be exploited

## Proof of concept

// write the proof of the vulnerability

## Patch 

``diff
--- xxx.php
+++ x.php
``

## Other recommandations

Optionnaly add a recommandation to help.

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/xxx/dddd-xxxxxxx.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-YYYY-XXXX)
* other links

## Timeline

If the CVE is published by Friends of Presta.

| Date | Action |
| -- | -- |
| YYYY-MM-DD | Discovery of the vulnerability |
| YYYY-MM-DD | Contact the author |
| YYYY-MM-DD | Other important milestone like contacts with PrestaShop team |
| YYYY-MM-DD | Request of a CVE ID |
| YYYY-MM-DD | Publish this security advisory and the CVE |
```

4. Publish a Pull Request.
5. Wait for the validation of our team.
