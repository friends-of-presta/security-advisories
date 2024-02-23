---
layout: post
title: "[CVE-2023-48188] Improper neutralization of SQL parameter in Opart Devis for PrestaShop"
categories: modules
author:
- Opart
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,opartdevis"
severity: "critical (9.8)"
---

In the module "Opart Devis" (opartdevis) up to version 4.6.12 from Opart for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-48188](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-48188)
* **Published at**: 2023-11-23
* **Platform**: PrestaShop
* **Product**: opartdevis
* **Impacted release**: >= 4.5.18 & <= 4.6.12 (4.6.13 fixed the vulnerability)  
* **Product author**: Opart
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `Translate::getModuleTranslation()` has a sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

This exploit uses a PrestaShop class stappled on all pages and most attackers can conceal the attack during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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

## Patch from 4.6.1

```diff
--- 4.6.1/modules/opartdevis/override/classes/Translate.php
+++ 4.6.2/modules/opartdevis/override/classes/Translate.php
...
                    LEFT JOIN '._DB_PREFIX_.'customer c ON c.id_customer = a.id_customer 
-                    WHERE id_opartdevis = '.Tools::getValue('id_opartdevis'));
+                    WHERE id_opartdevis = '.(int) Tools::getValue('id_opartdevis'));
                    $lang = new Language($id_lang);
```

Do not forget to check the installed override here : 

```diff
--- 4.6.1/override/classes/Translate.php
+++ 4.6.2/override/classes/Translate.php
...
                    LEFT JOIN '._DB_PREFIX_.'customer c ON c.id_customer = a.id_customer 
-                    WHERE id_opartdevis = '.Tools::getValue('id_opartdevis'));
+                    WHERE id_opartdevis = '.(int) Tools::getValue('id_opartdevis'));
                    $lang = new Language($id_lang);
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **opartdevis**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-11-29 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2022-11-29 | Contact Author to report it but was qualified CVSS 3.1 7.2/10 which is currently ignored |
| 2023-10-31 | [202 ecommerce](https://www.202-ecommerce.com/) qualified it critical |
| 2023-10-31 | Contact Author again to report that it's a critical issue and to get version scope |
| 2023-11-08 | Author confirms version scope |
| 2023-11-14 | Request a CVE ID |
| 2023-11-20 | Received CVE ID |
| 2023-11-23 | Publish this security advisory |

Opart thanks [TouchWeb](https://www.touchweb.fr) and [202 ecommerce](https://www.202-ecommerce.com/) for their courtesy and their help after the vulnerability disclosure.

## Links

* [Author product page](https://www.store-opart.fr/p/25-devis.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-48188)
