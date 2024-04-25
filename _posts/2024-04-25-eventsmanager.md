---
layout: post
title: "[CVE-2024-33271] Exposure of Private Personal Information to an Unauthorized Actor in FME Modules - Events Manager, Create events & Sell tickets Online module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 ecommerce.com
meta: "CVE,PrestaShop,eventsmanager"
severity: "medium (7.5), GDPR violation"
---

In the module "Events Manager, Create events & Sell tickets Online" (eventsmanager) up to version 4.4.0 from FME Modules for PrestaShop, a guest can download personal information without restriction.

## Summary

* **CVE ID**: [CVE-2024-33271](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33271)
* **Published at**: 2024-04-25
* **Platform**: PrestaShop
* **Product**: eventsmanager
* **Impacted release**: <= 4.3.0 (4.4.0 fixed the vulnerability)
* **Product author**: FME Modules
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
* **Severity**: medium (7.5), GDPR violation

## Description

Due to a lack of permissions control, a guest can download data from ps_customer such as : name / surname / email


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: none
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

## Possible malicious usage

* Steal personal data

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **eventsmanager**.

## Timeline

| Date | Action |
|--|--|
| 2024-01-18 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2024-01-18 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2024-01-18 | Contact PrestaShop Addons security Team confirms version scope |
| 2024-03-29 | Author provide a patch |
| 2024-04-23 | Received CVE ID |
| 2024-04-25 | Publish this security advisory |


## Links

* [Author product page](https://www.fmemodules.com/en/prestashop-modules/39-events-manager.html)
* [PrestaShop addons product page](https://addons.prestashop.com/en/reservation-rental-system/17275-events-manager-create-events-sell-tickets-online.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-33271)
