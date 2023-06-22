---
layout: post
title: "[CVE-2023-30195] Exposure of Private Personal Information to an Unauthorized Actor in Linea Grafica - Detailed Order module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,lgdetailedorder"
severity: "high (7.5), GDPR violation"
---

In the module "Detailed Order" (lgdetailedorder) from Linea Grafica for PrestaShop, a guest can download personal informations without restriction formatted in json.

## Summary

* **CVE ID**: [CVE-2023-30195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30195)
* **Published at**: 2023-06-22
* **Platform**: PrestaShop
* **Product**: lgdetailedorder
* **Impacted release**: <= 1.1.20 [considered to be "truly" fixed on 1.1.21 - see note below]
* **Product author**: Línea Gráfica
* **Weakness**: [CWE-359](https://cwe.mitre.org/data/definitions/359.html)
* **Severity**: high (7.5), GDPR violation

## Description

Due to a lack of permissions control, a guest can access all customers dataset including its personal informations (postal address, email, phone), orders and products bought.

Note : The author has deleted from its module the file that have been suffering from this leak for months, BUT did not set it to be "auto-deleted" during upgrades. Therefore, there are likely merchants out there with older versions who have updated their modules thinking they are safe. However, there is nothing safe about this since past upgrades do not auto-delete the implicated file. To ensure everyone has a "safe version", we decided to mark all versions up to 1.1.20 as impacted by this issue.

**WARNING** : Given that this is a serious data leak that could potentially engage the legal responsibility of third parties AND that it will absolutely bypass all application firewalls, we are obliged to provide no other information other than: update the module, delete the module, or restrict its access to a whitelist. Thank you for your understanding.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: low
* **Availability**: low

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

## Possible malicious usage

* Steal personal datas


## Other recommandations

* It’s recommended to delete the module or update it
* You should restrict access to this URI pattern : modules/lgdetailedorder/ to a given whitelist

## Timeline

| Date | Action |
|--|--|
| 2023-03-25 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-03-25 | Contact PrestaShop Addons security Team to confirm versions scope by author  |
| 2023-04-01 | Request a CVE ID |
| 2023-04-24 | Received CVE ID |
| 2023-05-25 | PrestaShop Addons confirms versions scopes |
| 2023-05-25 | Author provide a patch which auto-delete file from old versions |
| 2023-06-22 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/gestion-commandes/18065-apercu-acces-rapide-aux-details-des-commandes.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-30195)
