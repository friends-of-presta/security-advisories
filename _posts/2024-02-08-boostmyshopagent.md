---
layout: post
title: "[CVE-2024-24308] Improper neutralization of SQL parameter in Boostmyshop module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,boostmyshopagent"
severity: "critical (9.8)"
---

In the module "Boostmyshop" (boostmyshopagent) up to version 1.1.9 from Boostmyshop for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2024-24308](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24308)
* **Published at**: 2024-02-08
* **Platform**: PrestaShop
* **Product**: boostmyshopagent
* **Impacted release**: <= 1.1.9 (1.1.10 fixed the vulnerability)
* **Product author**: Boostmyshop
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The scripts changeOrderCarrier.php, relayPoint.php and shippingConfirmation.php has sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

Be warned that this module own others sensitives issues like BLIND SSRF which are ignored as all vulnerabilities with a CVSS 3.1 score < 7.5. See recommendations below.

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


## Patch from 1.1.9

```diff
--- 1.1.9/modules/boostmyshopagent/webservice/changeOrderCarrier.php
+++ XXXXX/modules/boostmyshopagent/webservice/changeOrderCarrier.php
        $query = new DbQuery();
        $query->select('*');
        $query->from('webservice_account');
-       $query->where('`key` = "' . $apiKey . '"');
+       $query->where('`key` = "' . pSQL($apiKey) . '"');
```

```diff
--- 1.1.9/modules/boostmyshopagent/webservice/relayPoint.php
+++ XXXXX/modules/boostmyshopagent/webservice/relayPoint.php
        $query = new DbQuery();
        $query->select('*');
        $query->from('webservice_account');
-       $query->where('`key` = "' . $apiKey . '"');
+       $query->where('`key` = "' . pSQL($apiKey) . '"');
```

```diff
--- 1.1.9/modules/boostmyshopagent/webservice/shippingConfirmation.php
+++ XXXXX/modules/boostmyshopagent/webservice/shippingConfirmation.php
        $query = new DbQuery();
        $query->select('*');
        $query->from('webservice_account');
-       $query->where('`key` = "' . $apiKey . '"');
+       $query->where('`key` = "' . pSQL($apiKey) . '"');
```

```diff
--- 1.1.9/modules/boostmyshopagent/webservice/productData.php
+++ XXXXX/modules/boostmyshopagent/webservice/productData.php
-   $shopId = Tools::getValue('shopId') ?: 1;
+   $shopId = (int) Tools::getValue('shopId') ?: 1;
```




## Other recommendations

* It’s recommended to upgrade to the latest version of the module **boostmyshopagent**.
* You must restrict access to modules/boostmyshopagent/webservice/ to a given whitelist to prevent BLIND SSRF chain exploit
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-11-02 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-11-02 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-11-03 | PrestaShop Addons security Team confirms version scope by author |
| 2023-12-11 | Author provide a patch |
| 2024-02-05 | Received CVE ID |
| 2024-02-08 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/comparison-shopping-prestashop/86128-boostmyshop.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-24308)
