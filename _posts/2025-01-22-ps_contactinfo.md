---
layout: post
title: "[CVE-2025-24027] ps_contactinfo has potential XSS due to usage of the nofilter tag in template"
categories: core
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,core"
severity: "medium (6.2)"
---

ps_contactinfo has a cross-site scripting (XSS) vulnerability in versions up to and including 3.3.2

## Summary

* **CVE ID**: [CVE-2025-24027](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24027)
* **Published at**: 2023-08-07
* **Advisory source**: PrestaShop
* **Platform**: PrestaShop
* **Product**: PrestaShop
* **Impacted release**: <= 3.3.2, 3.3.3 patched the issue
* **Product author**: PrestaShop
* **Weakness**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
* **Severity**: medium (6.2)

## Description

ps_contactinfo, a PrestaShop module for displaying store contact information, has a cross-site scripting (XSS) vulnerability in versions up to and including 3.3.2. This can not be exploited in a fresh install of PrestaShop, only shops made vulnerable by third party modules are concerned. For example, if the shop has a third party module vulnerable to SQL injections, then ps_contactinfo might execute a stored cross-site scripting in formatting objects. Commit d60f9a5634b4fc2d3a8831fb08fe2e1f23cbfa39 keeps formatted addresses from displaying a XSS stored in the database, and the fix is expected to be available in version 3.3.3. No workarounds are available aside from applying the fix and keeping all modules maintained and update.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: none
* **Privilege required**: high
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: low
* **Integrity**: high
* **Availability**: high 

**Vector string**: [CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:H)



## Links

* [PrestaShop product repository](https://github.com/PrestaShop/ps_contactinfo/security/advisories/GHSA-35pq-7pv2-2rfw)
* [Patch](https://github.com/PrestaShop/ps_contactinfo/commit/d60f9a5634b4fc2d3a8831fb08fe2e1f23cbfa39)


