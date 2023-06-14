---
layout: post
title: "[CVE-2023-31671] Improper neutralization of SQL parameter in Postfinance module"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Profileo.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,postfinance"
severity: "critical (9.8)"
---

SQL injection vulnerability found in the module "Postfinance" edited by Webbax for PrestaShop before 17.1.14. (17.1.14 fix the issue) allow a remote attacker to perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-31671](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31671)
* **Published at**: 2023-06-13
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: postfinance
* **Impacted release**: <= 17.1.13 (17.1.14 fix the issue).
* **Product author**: Webbax
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Before version 17.1.14, a sensitive SQL call in the class `PostfinanceValidationModuleFrontController::postProcess()` could be executed with a trivial HTTP call and exploited to forge a blind SQL injection by sending the `orderID` variable as a GET parameter. Its exploded version, `$get_id_cart` (a part of `orderID`), is then used in a SQL query.

This vulnerability can be exploited by an attacker to manipulate the SQL query and potentially gain unauthorized access to the database. It is important to update to version 17.1.14 or later to address this issue and ensure the security of the system.


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
* Copy/paste data from sensitive tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijacked emails


## Patch

```diff
--- a/modules/postfiannce/validation.php
+++ b/modules/postfiannce/validation.php
        if(Tools::strtoupper(sha1($string_crypt))==$sha){
        //if(Tools::strtoupper(sha1($string_crypt))==$sha && $getv_postfinance_upper['AMOUNT']==$cart->getOrderTotal(true,3)){
            
            $Postfinance = new Postfinance();
            
            // si le panier n'a pas été converti
-            $orderExists = (bool)Db::getInstance()->getValue('SELECT count(*) FROM `'._DB_PREFIX_.'orders` WHERE `id_cart`='.pSQL($get_id_cart));
+            $orderExists = (bool)Db::getInstance()->getValue('SELECT count(*) FROM `'._DB_PREFIX_.'orders` WHERE `id_cart`='. (int) $get_id_cart);
            if(
```

## Other recommendations

* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skilled because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-04-12 | Sensitive SQL parameter analysed by [202 ecommerce](https://www.202-ecommerce.com/) |
| 2023-04-14 | Contact the author |
| 2023-04-14 | Request a CVE ID |
| 2023-04-14 | The author confirm a fix is available on 17.1.14 |
| 2023-06-13 | Publication of this security advisory |


## Links

* [Author product page](https://shop.webbax.ch/modules-de-paiement/123-module-postfinance.html)
* [National Vulnerability Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31671)

