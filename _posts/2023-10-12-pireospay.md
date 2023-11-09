---
layout: post
title: "[CVE-2023-45375] Improper neutralization of SQL parameter in 01generator.com - PireosPay module for PrestaShop"
categories: modules
author:
- Touchweb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,pireospay"
severity: "critical (9.8)"
---

In the module "PireosPay" (pireospay) up to version 1.7.9 from 01generator.com for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-45375](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45375)
* **Published at**: 2023-10-12
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: pireospay
* **Impacted release**: <= 1.7.9 (1.7.10 fixed the vulnerability)
* **Product author**: 01generator.com
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `PireosPayValidationModuleFrontController::postProcess()` have sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards. 

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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
* Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails

## Proof of concept

```bash
curl -v -X POST -d 'ajax=true&MerchantReference=1%22;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--' 'https://preprod.XX/module/pireospay/validation'
```

## Patch from 1.7.9

```diff
--- 1.7.9/modules/pireospay/controllers/front/validation.php
+++ 1.7.10/modules/pireospay/controllers/front/validation.php
...
            if ($post_data_array[7]) {
-               $query = 'SELECT * FROM `' . _DB_PREFIX_ . 'pireospay` WHERE cart_id="' . $post_data_array[7] . '"';
+               $query = 'SELECT * FROM `' . _DB_PREFIX_ . 'pireospay` WHERE cart_id="' . pSQL($post_data_array[7]) . '"';
...
                                $customer = new Customer((int) $cart->id_customer);
                                $amount_sql = 'SELECT amount FROM ' . _DB_PREFIX_ .
-                               'pireospay where cart_id="' . addslashes($post_data_array[7]) .
+                               'pireospay where cart_id="' . pSQL($post_data_array[7]) .
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **pireospay**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-05-25 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-25 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-05-25 | PrestaShop Addons security Team confirm versions scope by author |
| 2023-06-22 | Author provide a patch |
| 2023-10-02 | Request a CVE ID |
| 2023-10-11 | Received CVE ID |
| 2023-10-12 | Publish this security advisory |


## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/paiement-carte-wallet/21279-pireospay.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45375)
