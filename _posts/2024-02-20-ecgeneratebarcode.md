---
layout: post
title: "[CVE-2024-24310] Improper neutralization of SQL parameter in Ether Création - Generate barcode on invoice / delivery slip module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ecgeneratebarcode"
severity: "high (8.8)"
---

In the module "Generate barcode on invoice / delivery slip" (ecgeneratebarcode) up to version 1.2.0 from Ether Création for PrestaShop, a guest can perform SQL injection in affected versions if the module is not installed OR if a secret accessible to administrator is stolen.


## Summary

* **CVE ID**: [CVE-2024-24310](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24310)
* **Published at**: 2024-02-20
* **Platform**: PrestaShop
* **Product**: ecgeneratebarcode
* **Impacted release**: <= 1.2.0 (2.0.0 fixed the vulnerability)
* **Product author**: Ether Création
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: high (8.8)

## Description

*Foreword : we are forced to tag privilege LOW (need a valid order reference) on the CVSS 3.1 score which make it a high vulnerability since it will be high if the module has never been installed OR (if the ECO_TOKEN_BARCODE configuration do not exist OR is empty), but keep in mind that for the majority of installations, the gravity is reduced to [CVSS 3.1 7.2/10](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)*

The script PHP `ajax.php` own a sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection if a valid Order reference is known.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Steal/Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch from 1.2.0

```diff
--- 1.2.0/modules/ecgeneratebarcode/ajax.php
+++ XXXXX/modules/ecgeneratebarcode/ajax.php
...
-if (Tools::getValue('ec_token') != Configuration::get('ECO_TOKEN_BARCODE')) {
+if (Tools::isEmpty('ec_token') || Tools::getValue('ec_token') !== Configuration::get('ECO_TOKEN_BARCODE')) {
...
-   $shop = Tools::getValue('idshop');
+   $shop = (int) Tools::getValue('idshop');

```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **ecgeneratebarcode**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-10-21 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-10-21 | Contact PrestaShop Addons security Team to confirm version scope |
| 2023-10-23 | Contact PrestaShop Addons security Team confirm version scope |
| 2024-02-05 | Received CVE ID |
| 2024-02-20 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/preparation-shipping/24123-generate-barcode-on-invoice-delivery-slip.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-24310)
