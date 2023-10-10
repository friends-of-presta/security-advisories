---
layout: post
title: "[CVE-2023-30154] Improper neutralization of SQL parameters in AfterMail (aftermailpresta) module from Shoprunners for PrestaShop"
categories: modules
author:
- Profileo.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,aftermailpresta"
severity: "critical (9.8)"
---

Multiple SQL injection vulnerabilities in the AfterMail (aftermailpresta) module from Shoprunners for PrestaShop, prior to version 2.2.1, allows remote attackers to execute arbitrary SQL commands via the `id_customer`, `id_conf`, `id_product` or `token` parameter in `aftermailajax.php` and via the `id_product` parameter in hooks `DisplayRightColumnProduct` and `DisplayProductButtons`.

## Summary

* **CVE ID**: [CVE-2023-30154](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30154)
* **Published at**: 2023-10-10
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: aftermailpresta
* **Impacted release**: < 2.2.1 (fixed in 2.2.1)
* **Product author**: Shoprunners
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

In the AfterMail (aftermailpresta) module for PrestaShop, multiple vulnerabilities can be exploited in versions prior to 2.2.1:
- An HTTP request can be manipulated using the `id_customer`, `id_conf`, `id_product` or `token` GET parameters, in the `/modules/aftermailpresta/aftermailajax.php` endpoint, enabling a remote attacker to perform a SQL injection.
- An HTTP request can be manipulated using `id_product` GET parameter, in the `/modules/aftermailpresta/aftermailpresta.php` endpoint (in `DisplayRightColumnProduct` and `DisplayProductButtons` hooks), enabling a remote attacker to perform a SQL injection.

Since one of these vulnerabilities relies on PrestaShop's hooks system, this will, by design, hide the module path. As a result, conventional frontend logs won't reveal that this vulnerability is being exploited. Only `POST /{product_path}` or `GET /{product_path}` will be visible in logs. Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

These issues are fixed in version 2.2.1, published in September 2022.

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

## Patch 

Multiple SQL injections fixed in `aftermailajax.php`:
```diff
--- modules/aftermailpresta/aftermailajax.php
+++ modules/aftermailpresta/aftermailajax.php
@@ -45,7 +45,7 @@ function subscribe()
     $id_conf = Tools::getValue('id_conf');
     $id_customer = Context::getContext()->customer->id;
     
-    $result = Db::getInstance()->ExecuteS('SELECT * FROM `' . _DB_PREFIX_ . 'aftermail_queue` ' . 'WHERE id_product = ' . $id_product . ' AND id_customer = ' . $id_customer);
+    $result = Db::getInstance()->ExecuteS('SELECT * FROM `' . _DB_PREFIX_ . 'aftermail_queue` ' . 'WHERE id_product = ' . (int)$id_product . ' AND id_customer = ' . (int)$id_customer);
     $taken = false;
     $saved = false;
     if (empty($result)) {
@@ -74,7 +74,7 @@ function unsubscribe()
     
     $token = Tools::getValue('token');
     
-    $success = Db::getInstance()->execute('DELETE FROM `' . _DB_PREFIX_ . 'aftermail_queue` WHERE id_product = ' . $id_product . ' AND id_customer = ' . $id_customer . ' AND id_aftermail_conf = ' . $id_conf . ' AND unsubscribe = "' . $token . '"');
+    $success = Db::getInstance()->execute('DELETE FROM `' . _DB_PREFIX_ . 'aftermail_queue` WHERE id_product = ' . (int)$id_product . ' AND id_customer = ' . (int)$id_customer . ' AND id_aftermail_conf = ' . (int)$id_conf . ' AND unsubscribe = "' . pSQL($token) . '"');
     $rows = Db::getInstance()->Affected_Rows();
     
     $mod = new AfterMailPresta();
@@ -91,7 +91,7 @@ function unsubscribeAll()
     $id_customer = Tools::getValue('customer_id');
     $token = Tools::getValue('token');
     
-    $success = Db::getInstance()->execute('DELETE FROM `' . _DB_PREFIX_ . 'aftermail_queue` WHERE id_customer = ' . $id_customer . ' AND unsubscribe_all = "' . $token . '"');
+    $success = Db::getInstance()->execute('DELETE FROM `' . _DB_PREFIX_ . 'aftermail_queue` WHERE id_customer = ' . (int)$id_customer . ' AND unsubscribe_all = "' . pSQL($token) . '"');
     $rows = Db::getInstance()->Affected_Rows();
     
     $mod = new AfterMailPresta();

```

SQL injection fixed in `aftermailpresta.php`:
```diff
--- modules/aftermailpresta/aftermailpresta.php
+++ modules/aftermailpresta/aftermailpresta.php
@@ -888,7 +888,7 @@ class AftermailPresta extends Module
                 $ids = explode(',', $row['subscribe_ids']);
                 foreach ($ids as $id) {
                     if ($row['subscribe_ids'] == '0' || trim($id) === Tools::getValue("id_product")) {
-                        $result2 = Db::getInstance()->ExecuteS('SELECT * FROM `' . _DB_PREFIX_ . 'aftermail_queue` ' . 'WHERE id_product = ' . Tools::getValue("id_product") . ' AND id_customer = ' . $this->context->customer->id);
+                        $result2 = Db::getInstance()->ExecuteS('SELECT * FROM `' . _DB_PREFIX_ . 'aftermail_queue` ' . 'WHERE id_product = ' . (int)Tools::getValue("id_product") . ' AND id_customer = ' . $this->context->customer->id);
                         if (empty($result2)) {
                             // 2. get frequencies
                             $frequencies = explode(',', $row['reminder_frequency']);
```

## Other recommendations

* It’s **highly recommended to upgrade the module** to the latest version or to **delete** the module if unused.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 2022-09-10 | Discovery of the vulnerability by Profileo.com |
| 2022-09-10 | Contacting the author of the module to notify him about the discovery |
| 2022-09-10 | The author confirmed the vulnerability and released the version 2.2.1 |
| 2023-04-02 | Contact the author back to clarify changes in the published version |
| 2023-04-21 | Receiving the CVE ID from Mitre |
| 2023-08-20 | Contact PrestaShop to clarify changes in the published version |
| 2023-08-21 | Contact the author to notify him about the upcoming publication |
| 2023-10-10 | Publication of this security advisory |

## Links

* [AfterMail Module](https://addons.prestashop.com/en/emails-notifications/8299-aftermail.html#specifications)
* [National Vulnerability Database CVE-2023-30154](https://nvd.nist.gov/vuln/detail/CVE-2023-30154)
