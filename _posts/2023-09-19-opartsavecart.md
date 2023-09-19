---
layout: post
title: "[CVE-2023-34575] Improper neutralization of SQL parameter in Opart Save Cart for PrestaShop"
categories: modules
author:
- Opart
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,opartsavecart"
severity: "critical (9.8)"
---

In the module "Opart Save Cart" (opartsavecart) up to version 2.0.7 from Opart for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-34575](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34575)
* **Published at**: 2023-09-19
* **Platform**: PrestaShop
* **Product**: opartsavecart
* **Impacted release**: <= 2.0.7 (2.0.8 fixed the vulnerability)
* **Product author**: Opart
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Methods `OpartSaveCartDefaultModuleFrontController::initContent()` and `OpartSaveCartDefaultModuleFrontController::displayAjaxSendCartByEmail()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

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
curl -v 'https://preprod.X/module/opartsavecart/default?action=delete&opartCartId=1;select(sleep(10));--'
```

## Patch from 2.0.7

```diff
--- 2.0.7/modules/opartsavecart/controllers/front/default.php
+++ 2.0.8/modules/opartsavecart/controllers/front/default.php
...
                     } else {
                         $idCart = Tools::getValue('opartCartId');
-                        $sql = "DELETE FROM `" . _DB_PREFIX_ . "opartsavecart` WHERE id_cart=" . $idCart . " AND id_customer=" . $idCustomer;
+                        $sql = "DELETE FROM `" . _DB_PREFIX_ . "opartsavecart` WHERE id_cart=" . (int)$idCart . " AND id_customer=" . (int)$idCustomer;
                         Db::getInstance()->execute($sql);
...
                         //check if cart exist for this customer
                         if (Tools::getIsset('opartCartId') && Tools::getValue('opartCartId')) {
                             $idCart = Tools::getValue('opartCartId');
-                            $sql = "SELECT * FROM `" . _DB_PREFIX_ . "opartsavecart` WHERE id_customer=" . $idCustomer . " AND id_cart=" . $idCart;
+                            $sql = "SELECT * FROM `" . _DB_PREFIX_ . "opartsavecart` WHERE id_customer=" . (int)$idCustomer . " AND id_cart=" . (int)$idCart;
                         } else if (Tools::getIsset('token') && Tools::getValue('token')) {
                             $token = Tools::getValue('token');
-                            $sql = "SELECT * FROM `" . _DB_PREFIX_ . "opartsavecart` WHERE token = '" . $token . "'";
+                            $sql = "SELECT * FROM `" . _DB_PREFIX_ . "opartsavecart` WHERE token = '" . pSQL($token) . "'";
                         }
...

             if (Validate::isEmail($email)) {
-                $sql = "SELECT * FROM `" . _DB_PREFIX_ . "opartsavecart` WHERE token = '" . $token . "'";
+                $sql = "SELECT * FROM `" . _DB_PREFIX_ . "opartsavecart` WHERE token = '" . pSQL($token) . "'";
                 $result = Db::getInstance()->getRow($sql);
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **opartsavecart**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-05-23 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-23 | Contact Author to confirm version scope |
| 2023-05-23 | Author confirms versions scope |
| 2023-05-24 | Request CVE ID |
| 2023-09-05 | Received CVE ID |
| 2023-09-19 | Publish this security advisory |

Opart thanks [TouchWeb](https://www.touchweb.fr) for its courtesy and its help after the vulnerability disclosure.

## Links

* [Author product page](https://www.store-opart.fr/p/20-sauvegarde-partage-lien-panier.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-34575)
