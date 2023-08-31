---
layout: post
title: "[CVE-2023-39641] Improper neutralization of SQL parameter in Active Design - Full Affiliates module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,psaffiliate"
severity: "critical (9.8)"
---

In the module "Full Affiliates" (psaffiliate) up to version 1.9.7 from Active Design for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-39641](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39641)
* **Published at**: 2023-08-31
* **Platform**: PrestaShop
* **Product**: psaffiliate
* **Impacted release**: <= 1.9.7 (1.9.8 fixed the vulnerability)
* **Product author**: Active Design
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `PsaffiliateGetaffiliatesdetailsModuleFrontController::initContent()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

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
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins' ajax scripts
* Rewrite SMTP settings to hijack emails


## Proof of concept


```bash
curl -v 'https://preprod.X/module/psaffiliate/getaffiliatesdetails?getHasBeenReviewed=1&ids_affiliate=1);select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--'
```

## Patch from 1.9.7

```diff
--- 1.9.7/modules/psaffiliate/controllers/front/getaffiliatesdetails.php
+++ 1.9.8/modules/psaffiliate/controllers/front/getaffiliatesdetails.php
class PsaffiliateGetaffiliatesdetailsModuleFrontController extends ModuleFrontController
{
    public function initContent()
    {
        parent::initContent();

        if (Tools::getValue('getHasBeenReviewed') && Tools::getValue('ids_affiliate')) {
            $ids_affiliate = Tools::getValue('ids_affiliate');
            $data = array();
            $data['success'] = true;
-           $result = Db::getInstance()->executeS('SELECT `id_affiliate` FROM `'._DB_PREFIX_.'aff_affiliates` WHERE `id_affiliate` IN ('.pSQL($ids_affiliate).') AND `has_been_reviewed`="0"');// phpcs:ignore
+           $result = Db::getInstance()->executeS('SELECT `id_affiliate` FROM `'._DB_PREFIX_.'aff_affiliates` WHERE `id_affiliate` IN ('.implode(',', array_map('intval', explode(',', Tools::getValue('ids_affiliate')))).') AND `has_been_reviewed`="0"');
            $data['result'] = $result;

```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **psaffiliate**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-04-18 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-04-18 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-04-19 | Request a CVE ID |
| 2023-05-09 | PrestaShop Addons security Team confirm versions scope |
| 2023-05-29 | PrestaShop Addons security Team confirm author provide a patch |
| 2023-08-29 | Received CVE ID |
| 2023-08-29 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/referencement-payant-affiliation/26226-full-affiliates.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-39641)
