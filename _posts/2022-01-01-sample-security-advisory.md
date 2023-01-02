---
layout: post
title: "Improper neutralization of an SQL parameter in PrestaShop XXXXX module"
categories: CVE
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
---


The PrestaShop e-commerce platform module XXXXX contains a Blind SQL injection vulnerability up to version a.b.c. This module is widely deployed and is a “Best seller” on the add-ons store.

## Summary

* **CVE ID**: *Requested*
* **Published at**: 2022-01-01
* **Advisory source**: Friends-of-presta.org
* **Vendor**: PrestaShop
* **Product**: XXXXX
* **Impacted release**: < a.b.d (a.b.d fixed the vulnerability)
* **Product author**: ZZZZZ
* **Weakness**: CW-89
* **Severity**: critical (9.4)

## Description

The method `abcdeModuleFrontController::initContent()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.


## CVSS base metrics

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

* Technical and personal data leaks
* Obtain admin access
* Remove all data of the linked PrestaShop

## Proof of concept

```bash
curl -v -X POST -d 'abcdef' 'https://domain.tld/'
```

## Patch of release a.b.c to a.b.d

```diff
--- a.b.c/XXXXX/controllers/front/abcde.php
+++ a.b.d/XXXXX/controllers/front/abcde.php
```


## Other recommandations

It’s recommended to upgrade to the lastest version of the module **XXXXX**.

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/)
