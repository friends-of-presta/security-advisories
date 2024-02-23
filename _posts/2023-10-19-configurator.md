---
layout: post
title: "[CVE-2023-43986] Improper neutralization of SQL parameter in DM Concept - Advanced configurator for customized product module for PrestaShop"
categories: modules
author:
- Dm Concept
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,configurator"
severity: "critical (9.8)"
---

In the module "Advanced configurator for customized product" (configurator) up to version 4.9.3 from DM Concept for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-43986](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43986)
* **Published at**: 2023-10-19
* **Platform**: PrestaShop
* **Product**: configurator
* **Impacted release**: <= 4.9.3 (4.9.4 fixed the vulnerability)
* **Product author**: DM Concept
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `ConfiguratorAttachment::getAttachmentByToken` has a sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards.

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

## Patch from 4.9.3

```diff
--- 4.9.3/modules/configurator/classes/ConfiguratorAttachment.php
+++ 4.9.4/modules/configurator/classes/ConfiguratorAttachment.php
    public static function getAttachmentByToken($token)
    {
        $query = new DbQuery();
        $query->select('*')
            ->from('configurator_attachment')
-           ->where('token = "' . $token . '"');
+           ->where('token = "' . pSQL($token) . '"');
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **configurator**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

DM Concept thanks TouchWeb for its courtesy and its help after the vulnerability disclosure.

## Timeline

| Date | Action |
|--|--|
| 2023-07-20 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-07-20 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-07-20 | PrestaShop Addons security Team confirm versions scope |
| 2023-07-20 | Author provide a patch |
| 2023-07-25 | Request a CVE ID |
| 2023-10-11 | Received CVE ID |
| 2023-10-19 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/declinaisons-personnalisation/20343-configurateur-avance-de-produit-sur-mesure-par-etape.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-43986)
