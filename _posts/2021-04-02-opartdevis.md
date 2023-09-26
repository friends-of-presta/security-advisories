---
layout: post
title: "[CVE-2020-16194] Authorization Bypass Through User-Controlled Key"
categories: modules
author:
- Opart
- layno
- c0dejump
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,opartdevis"
severity: "high (7.5)"
---

In the module "Opart Devis" (opartdevis) up to version 4.0.2 unauthenticated attackers can have access to any user's invoice and delivery address by exploiting an IDOR on the delivery_address and invoice_address fields.


## Summary

* **CVE ID**: [CVE-2020-16194](https://nvd.nist.gov/vuln/detail/CVE-2020-16194)
* **Published at**: 2020-06-07
* **Platform**: PrestaShop
* **Product**: opartdevis
* **Impacted release**: < 4.0.2 
* **Product author**: Opart
* **Weakness**: [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
* **Severity**: high (7.5)

## Description

The ajax script updatepos.php has a sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

Note : We didn't do semver versionning before 2018 - so consider all versions which matched this pattern : XX-XX-XX to be updated without delay.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: None
* **Availability**: None

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

## Possible malicious usage

* access to any user's invoice and delivery address

## recommendations

* It’s recommended to upgrade to the latest version of the module **opartdevis**.

## Timeline

| Date | Action |
|--|--|
| 2021-04-02 | Publish this security advisory |


Opart thanks [login-securite](https://github.com/login-securite) for its courtesy and its help.

## Links

* [Author product page](https://www.store-opart.fr/p/25-devis.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2020-16194)
