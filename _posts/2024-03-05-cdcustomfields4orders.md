---
layout: post
title: "[CVE-2024-25845] Improper neutralization of SQL parameter in Cleanpresta.com - CD Custom Fields 4 Orders module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,cdcustomfields4orders"
severity: "critical (9.8)"
---

In the module "CD Custom Fields 4 Orders" (cdcustomfields4orders) from Cleanpresta.com for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2024-25845](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25845)
* **Published at**: 2024-03-05
* **Platform**: PrestaShop
* **Product**: cdcustomfields4orders
* **Impacted release**: <= 1.0.0 (Author will never patch)
* **Product author**: Cleanpresta.com
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Ajax scripts ajax.php has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

Note : the author has discontinued support for its module, so you should consider uninstalling it. Be warned that it moved this critical issue to a front controller in 2.3.0 and put it under an unpredictable token, so the last version always has a high issue with a CVSS 3.1 score of [7.2/10](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)

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

## Patch from 1.0.0

```diff
--- 1.0.0/modules/cdcustomfields4orders/ajax.php
+++ XXXXX/modules/cdcustomfields4orders/ajax.php
...
		if(is_array($value)) $value = implode(',',$value);
-		$sql = 'REPLACE INTO '._DB_PREFIX_.'cd_cfo_values (`id_cd_cfo`, `id_cart`, `value`) VALUES ('.$field[2].', '.$id_cart.', "'.$value.'")';
+		$sql = 'REPLACE INTO '._DB_PREFIX_.'cd_cfo_values (`id_cd_cfo`, `id_cart`, `value`) VALUES ('.(int) $field[2].', '.(int) $id_cart.', "'.pSQL($value).'")';
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **cdcustomfields4orders**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-08-01 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-08-01 | Contact Author to confirm versions scope by author |
| 2024-01-24 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2024-01-24 | Contact PrestaShop Addons security Team confirms versions scope |
| 2024-02-22 | Received CVE ID |
| 2024-03-05 | Publish this security advisory |

## Links

* [Author page](www.cleanpresta.com)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-25845)
