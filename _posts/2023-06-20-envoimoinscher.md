---
layout: post
title: "[CVE-2023-30151] Improper neutralization of SQL parameters in the Boxtal (envoimoinscher) module from Boxtal for PrestaShop"
categories: module
author:
- Profileo.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,envoimoinscher"
severity: "critical (9.8)"
---

In the Boxtal (envoimoinscher) module from Boxtal for PrestaShop, after version 3.1.10, a SQL injection vulnerability allows remote attackers to execute arbitrary SQL commands via the `key` parameter in the `ajax.php` front controller.

## Summary

* **CVE ID**: [CVE-2023-30151](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30151)
* **Published at**: 2023-06-20
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: envoimoinscher
* **Impacted release**: > 3.1.10,<= 3.3.8 (latest version, not fixed, deprecated module to remove or to replace by BoxtalConnect)
* **Product author**: Boxtal
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

An HTTP request can be manipulated using the GET parameter `key` in the `/envoimoinscher/controllers/front/ajax.php` front controller, with `push` option, enabling a remote attacker to perform an anonymous SQL injection attack.

The issue is present in the latest version of the module. As of the date of publication of this advisory, Boxtal has announced they will not be releasing a new version to fix the issue. However, a patch is available for version 3.3.8 if requested from Boxtal.

Also, since the module is no longer maintained, **it is strongly recommended to remove it and migrate to Boxtal Connect**. In fact, the module has been deprecated since April 2019 and has been replaced with [Boxtal Connect](https://addons.prestashop.com/en/shipping-carriers/1755-boxtal-connect-turnkey-shipping-solution.html)

Note that the vulnerability was not detected in version 3.1.10. However, Boxtal wasn't able to confirm the exact version from which the vulnerability started.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller’s path during the exploit so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see “POST /” inside your conventional frontend logs**. Activating AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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
* Remove data on the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijacked emails

## Patch 

Note that the module is no longer maintained, therefore this patch might not be sufficient to fix all known security vulnerabilities from this module.
**It's strongly advised to remove the module and migrate to Boxtal Connect.**

```diff
--- a/includes/EnvoimoinscherModel.php
+++ b/includes/EnvoimoinscherModel.php
@@ -2754,7 +2754,7 @@ class EnvoimoinscherModel
         return $this->db->getValue(
             'SELECT count(*) FROM ' . _DB_PREFIX_ . 'emc_orders eo
                 JOIN ' . _DB_PREFIX_ . 'orders o ON o.id_order = eo.' . _DB_PREFIX_ . 'orders_id_order
-                WHERE eo.' . _DB_PREFIX_ . 'orders_id_order = ' . $order . ' AND eo.tracking_eor = "' . $key . '" '
+                WHERE eo.' . _DB_PREFIX_ . 'orders_id_order = ' . (int)$order . ' AND eo.tracking_eor = "' . pSQL($key) . '" '
         ) > 0;
     }
     public function orderWithTimeoutError($order)

```

## Other recommandations

* Completely remove the module since the module is no longer maintained or migrate to the new "Boxtal Connect" module (link available below)
* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skilled because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 2022-09-20 | Discovery of the vulnerability by Profileo in version 3.3.7 |
| 2022-09-20 | Contacting the editor (no reply) |
| 2023-03-17 | Contacting the editor |
| 2023-03-20 | The editor confirmed the vulnerability. No update will be released. |
| 2023-03-22 | Auditing the version 3.3.8 (latest version), confirming the vulnerability |
| 2023-04-02 | Requesting a CVE ID |
| 2023-06-20 | Publish this security advisory |

## Links

* [Download page of vulnerable module](https://help.boxtal.com/hc/fr/articles/360001342977-J-ai-besoin-du-module-PrestaShop-ancienne-version-Boxtal-Envoimoinscher-pour-mon-site)
* [Archive of version 3.3.8](https://resource.boxtal.com/ecommerce/legacy/prestashop/emc_prestashop1.6-3.3.8.zip)
* [New Boxtal Connect module](https://addons.prestashop.com/en/shipping-carriers/1755-boxtal-connect-turnkey-shipping-solution.html)
* [National Vulnerability Database CVE-2023-30151](https://nvd.nist.gov/vuln/detail/CVE-2023-30151)
