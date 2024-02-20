---
layout: post
title: "[CVE-2024-24309] Exposure of Sensitive Information to an Unauthorized Actor in Ecomiz - Survey TMA module for PrestaShop"
categories: modules
author:
- EcomiZ
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ecomiz_survey_tma"
severity: "medium (7.5), GDPR violation"
---

In the module "Survey TMA" (ecomiz_survey_tma) up to version 2.0.0 from Ecomiz for PrestaShop, a guest can download personal information without restriction.

## Summary

* **CVE ID**: [CVE-2024-24309](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24309)
* **Published at**: 2024-02-20
* **Platform**: PrestaShop
* **Product**: ecomiz_survey_tma
* **Impacted release**: <= 1.2.0 (2.0.0 fixed the vulnerability)
* **Product author**: Ecomiz
* **Weakness**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
* **Severity**: medium (7.5), GDPR violation

## Description

Due to a predictable token, a guest can access multiple technical information such as PrestaShop's version, a full list of modules with their versions, the database name/host/user/prefix (excluding password), and commercial statistics.


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

* Get precious technical data to facilitate others attacks like [CWE-89](https://cwe.mitre.org/data/definitions/89.html)


## Patch from 1.2.0

```diff
--- 1.2.0/modules/ecomiz_survey_tma/controllers/front/survey.php
+++ XXXXX/modules/ecomiz_survey_tma/controllers/front/survey.php
...
-      if($querytoken == "HARDCODED_TOKEN")
+      if($querytoken == Tools::encrypt($this->module->name))
```

## Other recommendations

* You should restrict access to all FC of the module ecomiz_survey_tma

## Timeline

| Date | Action |
|--|--|
| 2023-08-14 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-08-14 | Contact Author to confirm versions scope by author |
| 2023-08-14 | Author confirm versions scope |
| 2024-02-05 | Received CVE ID |
| 2024-02-20 | Publish this security advisory |

EcomiZ thanks [TouchWeb](https://www.touchweb.fr) for its courtesy and its help after the vulnerability disclosure.

## Links

* [Author page](https://www.ecomiz.com/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-24309)
