---
layout: post
title: "[CVE-2023-44024] Improper neutralization of SQL parameters in KnowBand - One Page Checkout, Social Login & Mailchimp module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,supercheckout"
severity: "critical (9.8)"
---

In the module "Module One Page Checkout, Social Login & Mailchimp" (supercheckout) up to version 8.0.3 from KnowBand for PrestaShop, an anonymous user can perform a SQL injection.


## Summary

* **CVE ID**: [CVE-2023-44024](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44024)
* **Published at**: 2023-10-05
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: supercheckout
* **Impacted release**: <= 8.0.3 (8.0.4 fixed the vulnerability)
* **Product author**: KnowBand
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `SupercheckoutSupercheckoutModuleFrontController::updateCheckoutBehaviour()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

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

## Patch from 8.0.3

```diff
--- 8.0.3/modules/supercheckout/controllers/front/supercheckout.php
+++ 8.0.4/modules/supercheckout/controllers/front/supercheckout.php
private static function transactionExists(string
...
        if (isset($result) && !empty($result) && $result != "") {
            //check if column exists or not
            $check_col_sql = 'SELECT count(*) FROM information_schema.COLUMNS
-                              WHERE COLUMN_NAME = "' . $field_name . '"
+                              WHERE COLUMN_NAME = "' . pSQL($field_name) . '"
                               AND TABLE_NAME = "' . _DB_PREFIX_ . 'kb_checkout_behaviour_stats"
                               AND TABLE_SCHEMA = "' . _DB_NAME_ . '"';
            $check_col = Db::getInstance(_PS_USE_SQL_SLAVE_)->getValue($check_col_sql);
            if ($check_col == 1) {
-               $sql = 'UPDATE ' . _DB_PREFIX_ . 'kb_checkout_behaviour_stats SET ' . pSQL($field_name) . ' = ' . (int) $filled . ' WHERE id_cart = ' . (int) $this->context->cart->id;
+               $sql = 'UPDATE ' . _DB_PREFIX_ . 'kb_checkout_behaviour_stats SET `' . bqSQL($field_name) . '` = ' . (int) $filled . ' WHERE id_cart = ' . (int) $this->context->cart->id;
                Db::getInstance()->execute($sql);
                if ((Tools::getValue('use_for_invoice') == 'true' || Tools::getValue('use_for_invoice') == true) && $field_name != 'email' && (strpos($field_name, '_invoice') == false)) {
-                   $sql = 'UPDATE ' . _DB_PREFIX_ . 'kb_checkout_behaviour_stats SET ' . pSQL($field_name) . '_invoice = ' . (int) $filled . ' WHERE id_cart = ' . (int) $this->context->cart->id;
+                   $sql = 'UPDATE ' . _DB_PREFIX_ . 'kb_checkout_behaviour_stats SET `' . bqSQL($field_name) . '_invoice` = ' . (int) $filled . ' WHERE id_cart = ' . (int) $this->context->cart->id;
                    Db::getInstance()->execute($sql);
                }
            }
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **supercheckout**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-07-24 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-07-24 | Contact PrestaShop Addons security Team to confirm version scope |
| 2023-07-25 | PrestaShop Addons security Team to confirm version scope |
| 2023-09-19 | Author provide a patch |
| 2023-09-22 | Request a CVE ID |
| 2023-09-28 | Received CVE ID |
| 2023-10-05 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/processus-rapide-commande/18016-one-page-checkout-social-login-mailchimp.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-44024)
