---
layout: post
title: "[CVE-2023-36263] Improper neutralization of SQL parameter in Opart limit quantity for PrestaShop"
categories: modules
author:
- Opart
- 202-ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,opartlimitquantity"
severity: "critical (9.8)"
---

In the module "Opart limit quantity" (opartlimitquantity), a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-36263](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36263)
* **Published at**: 2023-10-25
* **Platform**: PrestaShop
* **Product**: opartlimitquantity
* **Impacted release**: <= 1.4.5 (1.4.6 fixed the vulnerability)
* **Product author**: Opart
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Method `OpartlimitquantityAlertlimitModuleFrontController::displayAjaxPushAlertMessage()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING : Can be easily found by source auto-analysis - so it will be exploited soon to deploy webskimmer.**

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.


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
* Remove data on the associated PrestaShop
* Copy/past datas from sensibles tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijacked emails

## Patch from 1.4.6

```diff
--- 1.4.5/modules/opartlimitquantity/controllers/front/alertlimit.php
+++ 1.4.6/modules/opartlimitquantity/controllers/front/alertlimit.php
...
        if($id_attribute == 0){
 
-            $values = Db::getInstance()->getRow('SELECT quantity,batch_type FROM '._DB_PREFIX_.'opartlimitquantity_product_batch WHERE id_product = '.$id_product);
+            $values = Db::getInstance()->getRow('SELECT quantity,batch_type FROM '._DB_PREFIX_.'opartlimitquantity_product_batch WHERE id_product = '.(int)$id_product);
         }
         else{
-
-            $values = Db::getInstance()->getRow('SELECT quantity,batch_type FROM '._DB_PREFIX_.'opartlimitquantity_product_attribute_batch WHERE id_product = '.$id_product.' AND id_product_attribute = '.$id_attribute);
+            $values = Db::getInstance()->getRow('SELECT quantity,batch_type FROM '._DB_PREFIX_.'opartlimitquantity_product_attribute_batch WHERE id_product = '.(int)$id_product.' AND id_product_attribute = '.(int)$id_attribute);
             if(!$values){
-                 $values = Db::getInstance()->getRow('SELECT quantity,batch_type FROM '._DB_PREFIX_.'opartlimitquantity_product_batch WHERE id_product = '.$id_product);
+                 $values = Db::getInstance()->getRow('SELECT quantity,batch_type FROM '._DB_PREFIX_.'opartlimitquantity_product_batch WHERE id_product = '.(int)$id_product);
             }
         }
```

## Other recommandations

* It’s recommended to upgrade to the latest version of the module **opartlimitquantity**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` with a new longer arbitrary prefix. However, be warned that this is useless against blackhat with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these sets of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-12-12 | Issue discovered during a code review by [202-ecommerce.com](https://www.202-ecommerce.com/) |
| 2022-12-12 | Contact Author to confirm version scope |
| 2022-12-12 | Author confirms version scope |
| 2023-05-26 | Send a Mitre Request ID |
| 2023-10-25 | Publication of the security advisory |


Opart thanks [202-ecommerce.com](https://www.202-ecommerce.com/) for its courtesy and its help after the vulnerability disclosure.

## Links

* [Author product page](https://www.store-opart.fr/p/26-limit-quantity.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-36263)
