---
layout: post
title: "[CVE-2024-24304] Exposure of Sensitive Information to an Unauthorized Actor in Mailjet module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,mailjet"
severity: "medium (7.5), GDPR violation"
---

In the module "Mailjet" (mailjet) up to version 3.5.0 from Mailjet for PrestaShop, a guest can download personal information without restriction.

## Summary

* **CVE ID**: [CVE-2024-24304](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24304)
* **Published at**: 2024-02-06
* **Platform**: PrestaShop
* **Product**: mailjet
* **Impacted release**: <= 3.5.0 (3.5.1 fixed the vulnerability)
* **Product author**: Mailjet
* **Weakness**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
* **Severity**: medium (7.5), GDPR violation

## Description

Due to a broken access control, a guest can access multiple technical information such as a full list of modules with their versions, the admin link and a sensitive token.


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

## Patch from 3.5.0

--- 3.5.0/modules/mailjet/ajax.php
+++ 3.5.1/modules/mailjet/ajax.php
```diff
...
    require_once(realpath(dirname(__FILE__) . '/../../init.php'));
}

+$token_ok = Tools::getAdminToken(
+    'AdminModules' . (int) Tab::getIdFromClassName('AdminModules') . (int) Tools::getValue('id_employee')
+);
+
+if (Tools::getValue('token') != $token_ok) {
+    die('hack attempt');
+}
```

## Other recommendations

* You should restrict access to a given whitelist to these URI patterns /modules/mailjet/ajax/ and /modules/mailjet/ajax.php

## Timeline

| Date | Action |
|--|--|
| 2022-10-25 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2022-10-29 | FOP Security Team contact Author to confirm versions scope by author |
| 2022-11-17 | Author confirm versions scope and release a patch |
| 2024-02-05 | Received CVE ID |
| 2024-02-06 | Publish this security advisory |

## Links

* [Github page](https://github.com/mailjet/prestashop-mailjet-plugin-apiv3/releases/tag/v3.5.1)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-24304)
