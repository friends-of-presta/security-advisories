---
layout: post
title: "Data leak - transversal path"
categories: modules
author:
- Vitalyn.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,cdiscount"
severity: "High (7.5)"
---

**cdiscount** is a prestashop extension that bridges prestashop and the cdiscount marketplace. In affected versions a simple user can export personal data. This issue is fixed since version 4.4.61. Users are advised to upgrade.

## Summary

* **CVE ID**: 
* **Published at**: 2023-MM-DD
* **Advisory source**: PrestaShop
* **Platform**: PrestaShop
* **Product**: 
* **Impacted release**: < 4.6.61
* **Product author**: Common Services
* **Weakness**: [CWE-22] (https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: High (7.5)

## Description

A simple user can get personal data (GPDR), by using a simple URL

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N]([https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N&version=3.1))

## Possible malicious usage
none

## Proof of concept
xxx.php?action=yyy

## Other recommandations

* It’s recommended to upgrade to the lastest version of the module **cdiscount** up to 4.4.61

* Upgrade PrestaShop beyond 1.7.8.8 (and 8.0.2) to disable multiquery executions (separated by ";").
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [PrestaShop product repository](https://github.com/PrestaShop/blockwishlist/security/advisories/GHSA-2jx3-5j9v-prpp)
* [Patch](https://github.com/PrestaShop/blockwishlist/commit/b3ec4b85af5fd73f74d55390b226d221298ca084)

