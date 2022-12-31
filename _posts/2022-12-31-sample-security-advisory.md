---
layout: post
title: "This post demonstrates post content a security advisory"
categories: CVE
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
---


# Improper neutralization of an SQL parameter in PrestaShop XXXXX module

**CVE ID**: *Requested*
**Advisory author**: Friends-of-presta.org
**Vendor**: PrestaShop
**Product**: XXXXX
**Impacted release**: < 4.5.3 (4.5.3 fixed the vulnerability)
**Product author**: ZZZZZ
**Weakness**: CW-89
**Severity**: critical (9.4)

## Description

The method `abcdeModuleFrontController::initContent()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.


## CVSS base metrics

**Attack vector**: network
**Attack complexity**: low
**Privilege required**: none
**User interaction**: none
**Scope**: unchanged
**Confidentiality**: high
**Integrity**: high
**Availability**: low

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
--- 4.5.2/XXXXX/controllers/front/abcde.php
+++ 4.5.3/XXXXX/controllers/front/abcde.php
```


## Other recommandations

It’s recommended to upgrade to the lastest version of the module **XXXXX**.

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/)
