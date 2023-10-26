---
layout: post
title: "[CVE-2023-45899] Improper Access Control in superuser module edited by idnovate for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,superuser"
severity: "high (7.5)"
---

The module "idnovate" for PrestaShop incorrectly restricts access to the "connect as" feature from >= 2.3.5 and < 2.4.2 lets an attacker connect as any customer account. Release 2.4.2 fixed this security issue.

## Summary

* **CVE ID**: [CVE-2023-45899](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45899)
* **Published at**: 2023-10-26
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: superuser
* **Impacted release**: >= 2.3.5 and < 2.4.2 (2.4.2 fixed issue)
* **Product author**: idnovate
* **Weakness**: [CWE-305](https://cwe.mitre.org/data/definitions/305.html) [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
* **Severity**: high (7.5)


## Description

Before 2.4.2, an incorrect restriction of authentication `SuperUserSetuserModuleFrontController:init()` can be executed with a trivial http call and exploited to be connected as a customer.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: low
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)


## Possible malicious usage

* Personal data leaks
* Obtain customers access and potentially registered payment methods (if save credit cards enabled on a paymetn module)


## Patch

```diff
--- 2.4.1/modules/superuser/controllers/front/setuser.php
+++ 2.4.2/modules/superuser/controllers/front/setuser.php
@@ -31,16 +31,23 @@ class SuperUserSetuserModuleFrontControl
                 case 'getPw':
                     if (Tools::getValue('id')) {
                         $customer = new Customer((int)Tools::getValue('id'));
+                        $superuser_shop = $customer->id_shop;
+                        if (!$this->isBoLogged($superuser_shop)) {
+                            die('[SUPERUSER]Not BO logged.');
+                        }
+                        if (Shop::isFeatureActive()) {
+                            $superuser_shop = Tools::getValue('shop');
+                        }
                         $params = array(
                             'id_customer' => $customer->id,
                             'secure_key' => $customer->passwd,
-                            'superuser_shop' => $customer->id_shop,
+                            'superuser_shop' => $superuser_shop,
                             'use_last_cart' => '1',
                             'superuser_token' => Tools::encrypt($customer->id.$customer->passwd),
                             'time' => date('dmYhis')
                         );
                         $link = new Link();
-                        $controller_superuser = version_compare(_PS_VERSION_, '1.5', '<') ? (Configuration::get('PS_SSL_ENABLED') ? 'https://' : 'http://').$_SERVER['HTTP_HOST'].__PS_BASE_URI__.'modules/superuser/setuser.php?'.http_build_query($params) : $this->context->link->getModuleLink('superuser', 'setuser', $params, true, null, $customer->id_shop);
+                        $controller_superuser = version_compare(_PS_VERSION_, '1.5', '<') ? (Configuration::get('PS_SSL_ENABLED') ? 'https://' : 'http://').$_SERVER['HTTP_HOST'].__PS_BASE_URI__.'modules/superuser/setuser.php?'.http_build_query($params) : $this->context->link->getModuleLink('superuser', 'setuser', $params, true, null, $superuser_shop);
                         die($controller_superuser);
                     }
                     break;
@@ -63,6 +70,10 @@ class SuperUserSetuserModuleFrontControl
             $id_customer = $order->id_customer;
         }
         $customer = new Customer((int)$id_customer);
+        $selected_customer_shop = new Shop((int)$customer->id_shop);
+        if (!$this->isBoLogged($superuser_shop)) {
+            Tools::redirect(_PS_BASE_URL_.__PS_BASE_URI__);
+        }
         $customer_secure_key = $customer->passwd;
         if (Tools::getValue('superuser_shop')) {
             $shop = new Shop((int)Tools::getValue('superuser_shop'));
```


## Other recommandations

* It’s recommended to upgrade to the latest version of the module **superuser**.


## Timeline

| Date | Action |
|--|--|
| 2022-10-11 | Vunlnerability found during a audit by [202 ecommerce](https://www.202-ecommerce.com/) |
| 2023-10-12 | The author confirm the vulenrability |
| 2023-10-13 | The author publish the release 2.4.2 |
| 2023-10-09 | Request a CVE ID |
| 2023-10-25 | Publication of this advisory |


## Links

* [Author product page](https://addons.prestashop.com/en/customer-service/7280-super-user-log-in-as-customer.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45899)

