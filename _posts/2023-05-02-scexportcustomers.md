---
layout: post
title: "[CVE-2023-30282] Exposure of Private Personal Information to an Unauthorized Actor in SC Export Customers module for PrestaShop"
categories: modules
author:
- Store Commander
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,scexportcustomers"
severity: "high (7.5), GDPR violation"
---

In the module "SC Export Customers" (scexportcustomers), a guest can download personal informations without restriction.

## Summary

* **CVE ID**: [CVE-2023-30282](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30282)
* **Published at**: 2023-05-02
* **Platform**: PrestaShop
* **Product**: scexportcustomers
* **Impacted release**: <= 3.6.1
* **Product author**: Store Commander
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
* **Severity**: high (7.5), GDPR violation

## Description

Due to a lack of permissions control, a guest can access exports from the module which can lead to leak of personal informations from ps_customer table sush as name / surname / email


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: none
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

## Possible malicious usage

* Steal personal datas

## Other recommandations

* It's recommended to delete the module if not used or contact Store Commander
* You should restrict access to this URI pattern : modules/scexportcustomers/ to a given whitelist

## Timeline

| Date | Action |
|--|--|
| 2022-12-08 | Issue discovered after a security audit by [TouchWeb](https://www.touchweb.fr) |
| 2022-12-08 | Contact Author |
| 2022-12-12 | Author provide patch |
| 2023-03-30 | Request a CVE ID |
| 2023-04-27 | Received CVE ID |
| 2023-05-02 | Publish this security advisory |


Store Commander thanks [TouchWeb](https://www.touchweb.fr) for its courtesy and its help after the vulnerability disclosure.

## Links

* [Store Commander export customer module product page](https://www.storecommander.com/fr/modules-complementaires/480-export-clients-pro.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-30282)
