---
layout: post
title: "[CVE-2023-45256] Improper neutralization of SQL parameters in Monetico Paiement module from EuroInformation for PrestaShop"
categories: modules
author:
- Profileo.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,moneticopaiement"
severity: "critical (9.8)"
---

In the module Monetico Paiement (MoneticoPaiement), multiple insecure parameters can allow a remote attacker to perform a SQL injection attack.

## Summary

* **CVE ID**: [CVE-2023-45256](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45256)
* **Published at**: 2025-06-10
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: MoneticoPaiement
* **Impacted release**: <= 1.1.0 (1.1.1 fixed issue)
* **Product author**: Monetico Paiement/EuroInformation
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Up to 1.1.0, SQL queries in FrontController endpoints `transaction.php`, `callback.php` and `validation.php` can be exploited with trivial HTTP calls to forge SQL injections through the POST or GET submitted `TPE`, `MAC`, `societe`, `reference` and `aliascb` variables.

This vulnerability relies on PrestaShop's FrontController, which allows attackers to hide the module controller's path during the exploit. As a result, conventional frontend logs won't reveal that this vulnerability is being exploited. Only `POST /` will be visible in logs. Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admin's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch

```diff
--- a/modules/MoneticoPaiement/MoneticoPaiement.php
+++ b/modules/MoneticoPaiement/MoneticoPaiement.php
@@ -137,7 +137,7 @@ class MoneticoPaiementCodeSite extends \ObjectModel
             $sql = new \DbQuery();
             $sql->select('*');
             $sql->from('monetico_code_site_3dsv2');
-            $sql->where('code_site_id = ' . $this->getIdCodeSite());
+            $sql->where('code_site_id = ' . (int)$this->getIdCodeSite());
 
             $this->set3DSV2(Db::getInstance()->executeS($sql));
         }
@@ -388,8 +388,8 @@ class MoneticoPaiementCodeSite extends \ObjectModel
             $sql = new \DbQuery();
             $sql->select('*');
             $sql->from('monetico_code_site_opts');
-            $sql->where('code_site_id = ' . $this->getIdCodeSite());
-            $sql->where('opt = "' . $name . '"');
+            $sql->where('code_site_id = ' . (int)$this->getIdCodeSite());
+            $sql->where('opt = "' . pSQL($name) . '"');
 
             $options = Db::getInstance()->executeS($sql);
             if ($multiple_option) {
@@ -416,7 +416,7 @@ class MoneticoPaiementCodeSite extends \ObjectModel
             $sql = new \DbQuery();
             $sql->select('*');
             $sql->from('monetico_code_site_3dsv2');
-            $sql->where('code_site_id = ' . $this->getIdCodeSite());
+            $sql->where('code_site_id = ' . (int)$this->getIdCodeSite());
 
             $data_3dsv2 = Db::getInstance()->executeS($sql);
         }
@@ -476,8 +476,8 @@ class MoneticoPaiementCodeSite extends \ObjectModel
             $sql = new \DbQuery();
             $sql->select('*');
             $sql->from('monetico_code_site_opts');
-            $sql->where('code_site_id = ' . $this->getIdCodeSite());
-            $sql->where('opt = "' . $name . '"');
+            $sql->where('code_site_id = ' . (int)$this->getIdCodeSite());
+            $sql->where('opt = "' . pSQL($name) . '"');
 
             $option = Db::getInstance()->executeS($sql);
```

```diff
--- a/modules/MoneticoPaiement/class/MoneticoPaiementEPT.php
+++ b/modules/MoneticoPaiement/class/MoneticoPaiementEPT.php
@@ -312,7 +312,7 @@ class MoneticoPaiementEPT extends \ObjectModel
         $sql = new \DbQuery();
         $sql->select('*');
         $sql->from('monetico_code_site');
-        $sql->where('code_site_ept_id = ' . $this->id_ept);
+        $sql->where('code_site_ept_id = ' . (int)$this->id_ept);
         return Db::getInstance()->executeS($sql);
     }
 
@@ -108,7 +108,7 @@ class MoneticoPaiementHelper
         $sql = new \DbQuery();
         $sql->select('ept_number');
         $sql->from('monetico_ept');
-        $sql->where('id_ept = ' . $id);
+        $sql->where('id_ept = ' . (int)$id);
 
         $row = Db::getInstance()->getValue($sql);
         return $row ?? '';
@@ -123,10 +123,10 @@ class MoneticoPaiementHelper
         $sql = new \DbQuery();
         $sql->select('ept_mac');
         $sql->from('monetico_ept');
-        $sql->where('ept_number = "' . $ept_number . '"');
+        $sql->where('ept_number = "' . pSQL($ept_number) . '"');
 
         if (isset($id)) {
-            $sql->where('id_ept != ' . $id);
+            $sql->where('id_ept != ' . (int)$id);
         }
 
         $row = Db::getInstance()->getValue($sql);

@@ -144,7 +144,7 @@ class MoneticoPaiementHelper
         $sql = new \DbQuery();
         $sql->select('*');
         $sql->from('monetico_code_site');
-        $sql->where('code_site_name = "' . $code_societe_name . '"');
+        $sql->where('code_site_name = "' . pSQL($code_societe_name) . '"');
 
         return Db::getInstance()->getRow($sql);
     }
@@ -159,7 +159,7 @@ class MoneticoPaiementHelper
         $sql = new \DbQuery();
         $sql->select('*');
         $sql->from('monetico_ept');
-        $sql->where('ept_number = "' . $ept_number . '"');
+        $sql->where('ept_number = "' . pSQL($ept_number) . '"');
 
         return Db::getInstance()->getRow($sql);
     }
@@ -222,8 +222,8 @@ class MoneticoPaiementHelper
                 $sql = new \DbQuery();
                 $sql->select('code_site_id');
                 $sql->from('monetico_code_site_opts');
-                $sql->where(' `opt` = "' . $filter_key . '"');
-                $sql->where('`value` = "' . $filter_value . '"');
+                $sql->where(' `opt` = "' . pSQL($filter_key) . '"');
+                $sql->where('`value` = "' . pSQL($filter_value) . '"');
 
                 $options = Db::getInstance()->executeS($sql);
                 $filter_ids = [];
@@ -263,7 +263,7 @@ class MoneticoPaiementHelper
             $sql = new \DbQuery();
             $sql->select('*');
             $sql->from('monetico_code_site');
-            $sql->where('id_code_site IN (' . $code_site_where_in . ')');
+            $sql->where('id_code_site IN (' . pSQL($code_site_where_in) . ')');
             $sql->where('code_site_active = 1');
             $result = Db::getInstance()->executeS($sql);
             foreach ($result as $code_site) {

@@ -288,8 +288,8 @@ class MoneticoPaiementHelper
         $sql = new \DbQuery();
         $sql->select('count(*)');
         $sql->from('monetico_code_site_opts');
-        $sql->where('`code_site_id` = "' . $code_site_id . '"');
-        $sql->where(' `opt` = "' . $filter_key . '"');
+        $sql->where('`code_site_id` = "' . pSQL($code_site_id) . '"');
+        $sql->where(' `opt` = "' . pSQL($filter_key) . '"');
 
         return (int)Db::getInstance()->getValue($sql);
     }
@@ -308,9 +308,9 @@ class MoneticoPaiementHelper
         $sql = new \DbQuery();
         $sql->select('count(*)');
         $sql->from('monetico_code_site_opts');
-        $sql->where('`code_site_id` = "' . $code_site_id . '"');
-        $sql->where(' `opt` = "' . $filter_key . '"');
-        $sql->where(' `value` = "' . $fitler_value . '"');
+        $sql->where('`code_site_id` = "' . (int)$code_site_id . '"');
+        $sql->where(' `opt` = "' . pSQL($filter_key) . '"');
+        $sql->where(' `value` = "' . pSQL($fitler_value) . '"');
 
         return (int)Db::getInstance()->getValue($sql);
     }
@@ -386,7 +412,7 @@ class MoneticoPaiementHelper
         $sql = new \DbQuery();
         $sql->select('*');
         $sql->from('monetico_transaction');
-        $sql->where(' `order_ref` = "' . $order_ref . '"');
+        $sql->where(' `order_ref` = "' . pSQL($order_ref) . '"');
         return Db::getInstance()->getRow($sql);
     }
 
@@ -472,7 +498,7 @@ class MoneticoPaiementHelper
         $sql = new \DbQuery();
         $sql->select('id');
         $sql->from('monetico_alias_bc');
-        $sql->where(' `alias` = "' . $alias . '"');
+        $sql->where(' `alias` = "' . pSQL($alias) . '"');
         $row = Db::getInstance()->getValue($sql);
         return $row ?? '';
     }
```

## Other recommendations

* It’s **highly recommended to upgrade the module** to the latest version or to **delete** the module if unused.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 2023-08-13 | Discovery of the vulnerability by Profileo |
| 2023-08-13 | Disclosing the vulnerability to Monetico Paiement and Euro-Information |
| 2023-08-17 | Confirmation of the vulnerability by the author |
| 2023-08-18 | Release of the fix by the author in version 1.1.1 |
| 2023-08-18 | Author warned customers of the vulnerability and request the upgrade to version 1.1.1 |
| 2023-08-18 | Requesting a CVE ID to Mitre |
| 2023-10-13 | Author requests a one-month delay before public disclosure |
| 2025-06-10 | Profileo publish the vulnerability |


## Links

* [Download page of Monetico module](https://www.monetico-paiement.fr/fr/installer/telechargements/kit_telechargeable.aspx?_tabi=I0&_pid=ValidateLicencePage)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45256)
