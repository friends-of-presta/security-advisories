---
layout: post
title: "[CVE-2023-33664] Improper neutralization of a SQL parameter in aicombinationsonfly module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,aicombinationsonfly"
severity: "critical (9.8)"
---

In the module "Combinations generated on fly for your store" (aicombinationsonfly) for PrestaShop, an attacker can perform SQL injection before 0.3.1. Release 0.3.1 fixed this security issue.

## Summary

* **CVE ID**: [CVE-2023-33664](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33664)
* **Published at**: 2023-06-28
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: aicombinationsonfly
* **Impacted release**: < 0.3.1 (0.3.1 fixed the vulnerability)
* **Product author**: ai-dev
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Up to 0.3.0, a sensitive SQL calls in file `includes/ajax.php` can be executed with a trivial http call and exploited to forge a blind SQL injection throught the POST or GET submitted `attributes` variables.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
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

## Patch

```diff
--- a/modules/aicombinationsonfly/includes/ajax.php
+++ b/modules/aicombinationsonfly/includes/ajax.php
@@ -50,7 +50,7 @@ switch (Tools::getValue('action')) {
             die();
         }
     
-        $attributes = array_map('intval', explode(',', Tools::getValue('attributes')));
+        $attributes = explode(',', Tools::getValue('attributes'));
         if ($combination_id = AiCombinationsOnFlyFunctions::createCombination((int)Tools::getValue('product'), $attributes, 0, 1, Tools::getValue('module'), $shop_id)) {
             /* Get data */
             $data = Db::getInstance()->getRow(

--- a/modules/aicombinationsonfly/includes/functions.php
+++ b/modules/aicombinationsonfly/includes/functions.php
    public static function createCombination($product_id, $values, $default_on = 0, $aicof_value = 0, $module = '', $shop_id = 0)
    {
+       $values = array_map('intval', $values);
        //  If module is defined, change values if needed
        $combination_values = array();
```

## Other recommandations

* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-05-08 | Vunlnerability found during a audit by [202 ecommerce](https://www.202-ecommerce.com/) |
| 2023-05-10 | Contact the author |
| 2023-05-12 | The author confirm the issue and supply a fixed release |
| 2023-03-12 | Request a CVE ID |
| 2023-06-28 | Publication of this advisory |


## Links

* [Author product page](https://www.boutique.ai-dev.fr/en/ergonomie/61-combinations-on-fly.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-33664)

