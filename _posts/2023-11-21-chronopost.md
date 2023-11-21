---
layout: post
title: "[CVE-2023-45377] Improper neutralization of SQL parameter in Chronopost - Chronopost Official module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,chronopost"
severity: "critical (9.8)"
---

In the module "Chronopost Official" (chronopost) up to version 6.4.0 from Chronopost for PrestaShop, a guest can perform SQL injection in affected versions if the module is not installed OR if a secret accessible to administrator is stolen.


## Summary

* **CVE ID**: [CVE-2023-45377](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45377)
* **Published at**: 2023-11-21
* **Platform**: PrestaShop
* **Product**: chronopost
* **Impacted release**: <= 6.2.1 (6.4.0 fixed the vulnerability)
* **Product author**: Chronopost Official
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

*Foreword : we are forced to tag privilege NONE on the CVSS 3.1 score which make it a critical vulnerability since it will be critical if the module has never been installed OR (if the CHRONOPOST_SECRET configuration do not exist OR is empty), but keep in mind that for the majority of installations, the gravity is reduced to [CVSS 3.1 7.2/10](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)*

The script PHP `cancelSkybill.php` own a sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING**: Be informed that the partial access control affects other scripts on the module, you should apply "Other Recommendations"

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Steal/Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch from 6.2.1

```diff
--- 6.2.1/modules/chronopost/async/cancelSkybill.php
+++ 6.4.0/modules/chronopost/async/cancelSkybill.php
...
-if (!Tools::getIsset('shared_secret') || Tools::getValue('shared_secret') != Configuration::get('CHRONOPOST_SECRET')) {
+if (Tools::isEmpty('shared_secret') || Tools::getValue('shared_secret') !== Configuration::get('CHRONOPOST_SECRET')) {
    die('Secret does not match.');
}
...
$LTRequest = DB::getInstance()->executeS(
    'SELECT lt, account_number FROM '
-    . _DB_PREFIX_ . 'chrono_lt_history WHERE id_order = ' . (int)Tools::getValue('id_order') . ' AND `cancelled` IS NULL AND lt = "' . Tools::getValue('skybill') . '"'
+    . _DB_PREFIX_ . 'chrono_lt_history WHERE id_order = ' . (int)Tools::getValue('id_order') . ' AND `cancelled` IS NULL AND lt = "' . pSQL(Tools::getValue('skybill')) . '"'
);

```

## Other recommendations

* Since this author always force its customers to use the same password on FTP links, you must if applicable, delete all FTP users which suffer of a predictable name such as "chronopost"
* You should consider restricting the access of modules/chronopost/async/ to a whitelist
* It’s recommended to upgrade to the latest version of the module **chronopost**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-03-15 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-03-15 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-05-05 | Recontact PrestaShop Addons security Team to confirm version scope by author |
| 2023-10-06 | Request a CVE ID |
| 2023-10-11 | Received CVE ID |
| 2023-10-30 | Recontact PrestaShop Addons security Team to confirm version scope by author |
| 2023-10-30 | PrestaShop Addons security Team confirms version scope and confirms the official patch |
| 2023-11-21 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/transporteurs/19561-chronopost-officiel.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45377)
