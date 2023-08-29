---
layout: post
title: "[CVE-2023-39642] Improper neutralization of SQL parameter in Carts Guru | Marketing automation multicanal module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,cartsguru"
severity: "critical (9.8)"
---

In the module "Carts Guru | Marketing automation multicanal" (cartsguru) up to versions 2.4.2 from Carts Guru for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-39642](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39642)
* **Published at**: 2023-08-29
* **Platform**: PrestaShop
* **Product**: cartsguru
* **Impacted release**: <= 2.4.2 [considered to be "truly" fixed on 2.4.3 - see note below]
* **Product author**: Carts Guru
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The method `CartsGuruCatalogModuleFrontController::display()` and the ajax script controllers14/catalog.php has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

Note : The author has deleted from its module the files that have been suffering from critical vulnerabilities for months, BUT did not set them to be "auto-deleted" during upgrades. Therefore, there are likely merchants out there with older versions who have updated their modules thinking they are safe. However, there is nothing safe about this since past upgrades do not auto-delete the implicated files. To ensure everyone has a "safe version", we decided to mark all versions up to 2.4.3 as impacted by this issue.

**WARNING** : This exploit is actively used to deploy webskimmer to massively steal credit cards. 

One of these exploits uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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


## Proof of concept


```bash
curl -v 'https://preprod.XX/modules/cartsguru/controllers14/catalog.php?cartsguru_catalog_limit=1;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--'
curl -v 'https://preprod.XX/?fc=module&module=cartsguru&controller=catalog&cartsguru_catalog_limit=1;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--'
```

## Patch from 1.4.19

These files does not exist if you started working with Cartsguru beyond 2.X versions BUT if you worked with them BEFORE 2.X versions - you should own it.

```diff
--- 1.4.19/controllers14/catalog.php
+++ XXXXXX/controllers14/catalog.php
if ($isMultiStoreSupported) {
    $id_shop = (int)Context::getContext()->shop->id;

    $sql .= ' JOIN ' . _DB_PREFIX_ . 'product_shop s ON p.id_product = s.id_product WHERE id_shop = ' . $id_shop;
    $sqlTotal .= ' JOIN ' . _DB_PREFIX_ . 'product_shop s ON p.id_product = s.id_product WHERE id_shop = ' . $id_shop;
}

// Set limit and offset
-$sql .= ' LIMIT ' . pSQL($limit) . ' OFFSET ' . pSQL($offset);
+$sql .= ' LIMIT ' . (int) $limit . ' OFFSET ' . (int) $offset;
```

```diff
--- 1.4.19/controllers/front/catalog.php
+++ XXXXXX/controllers/front/catalog.php
        if (CartsGuruHelper::isMultiStoreSupported()) {
            $id_shop = (int)Context::getContext()->shop->id;

            $sql .= ' WHERE id_shop = ' . $id_shop;
            $sqlTotal .= ' WHERE id_shop = ' . $id_shop;
        }
        // Set limit and offset
-       $sql .= ' LIMIT ' . pSQL($limit) . ' OFFSET ' . pSQL($offset);
+       $sql .= ' LIMIT ' . (int) $limit . ' OFFSET ' . (int) $offset;
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **cartsguru**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-10-11 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2022-10-12 | Author contacted and provide a patch |
| 2023-04-18 | Contact PrestaShop Addons security Team to confirm versions scope by author  |
| 2023-04-19 | Request a CVE ID |
| 2023-05-09 | PrestaShop Addons confirms versions scopes |
| 2023-05-24 | Author provide a patch which auto-delete files from old versions |
| 2023-08-25 | Received CVE ID |
| 2023-08-29 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/remarketing-paniers-abandonnes/22077-carts-guru-marketing-automation-multicanal.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-39642)
