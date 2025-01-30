---
layout: post
title: "[CVE-2025-24027] ps_contactinfo has potential XSS due to usage of the nofilter tag in template"
categories: core
author:
- Friends-Of-Presta.org
- TouchWeb.fr
meta: "CVE,PrestaShop,core"
severity: "low (4.1)"
---

ps_contactinfo has a cross-site scripting (XSS) weakness (which is not a standalone vulnerability) in versions up to and including 3.3.2

## Summary

* **CVE ID**: [CVE-2025-24027](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24027)
* **Published at**: 2025-01-22
* **Advisory source**: PrestaShop
* **Platform**: PrestaShop
* **Product**: PrestaShop
* **Impacted release**: <= 3.3.2, 3.3.3 patched the issue
* **Product author**: PrestaShop
* **Weakness**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
* **Severity**: low (4.1)

## Description

The ps_contactinfo module for PrestaShop, used to display store contact information, contains a cross-site scripting (XSS) **weakness** in versions up to and including 3.3.2. 

This weakness could lead to a chained vulnerability **if and only if** the store uses a third-party module vulnerable to SQL injection, as ps_contactinfo might execute stored XSS when rendering formatted objects.

The issue is addressed in commit d60f9a5634b4fc2d3a8831fb08fe2e1f23cbfa39, which prevents formatted addresses from executing stored XSS present in the database. The fix will be included in version 3.3.3 of the module.

No workarounds are currently available, other than applying the fix and ensuring that all modules are properly maintained and up to date.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: none
* **Privilege required**: high
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: low
* **Integrity**: low
* **Availability**: low 

**Vector string**: [CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L)

## Timeline

| Date | Action |
|--|--|
| 2025-01-22 | Publish this security advisory |
| 2025-01-30 | New description and score claim by TouchWeb since it's a chain vulnerability |

## Links

* [PrestaShop product repository](https://github.com/PrestaShop/ps_contactinfo/security/advisories/GHSA-35pq-7pv2-2rfw)
* [Patch](https://github.com/PrestaShop/ps_contactinfo/commit/d60f9a5634b4fc2d3a8831fb08fe2e1f23cbfa39)


