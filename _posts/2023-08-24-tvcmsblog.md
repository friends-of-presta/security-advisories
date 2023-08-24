---
layout: post
title: "[CVE-2023-39650] Improper neutralization of SQL parameters in Theme Volty CMS Blog module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Vitalyn.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,theme volty,tvcmsblog"
severity: "critical (9.8)"
---

In the module "Theme Volty CMS Blog" (tvcmsblog) up to versions 4.0.1 from Theme Volty for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-39650](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39650)
* **Published at**: 2023-08-24
* **Platform**: PrestaShop
* **Product**: tvcmsblog
* **Impacted release**: <= 4.0.1 (4.0.2 fixed the vulnerability)
* **Product author**: Theme Volty
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The methods `TvcmsVideoTabConfirmDeleteModuleFrontController::run()` and `TvcmsVideoTabSaveVideoModuleFrontController::run()` have sensitive SQL calls that can be executed with a trivial HTTP call and exploited to forge a SQL injection.

If your server do not manage correctly these HTTP headers (which will be the case for all servers not managed by a professional system administrator), you are concerned: 

- CLIENT_IP
- X_FORWARDED_FOR
- X_FORWARDED
- FORWARDED_FOR
- FORWARDED

See recommendations if needed about this.

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

## Patch from 4.0.1

```diff
--- 4.0.1/tvcmsblog/controllers/front/single.php
+++ 4.0.2/tvcmsblog/controllers/front/single.php
...
    public function initContent()
    {
        $ipaddress = '';
        if (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED'])) {
            $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
        } elseif (isset($_SERVER['HTTP_FORWARDED_FOR'])) {
            $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
        } elseif (isset($_SERVER['HTTP_FORWARDED'])) {
            $ipaddress = $_SERVER['HTTP_FORWARDED'];
        } elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $ipaddress = $_SERVER['REMOTE_ADDR'];
        } else {
            $ipaddress = 'UNKNOWN';
        }
        $blogid = $this->blogpost['id_tvcmsposts'];

-       $select_data = 'SELECT MAX(id_view) as max_id FROM `' . _DB_PREFIX_ . 'tvcmsposts_view` where `id_tvcmsposts` = ' . $blogid . ' AND `ipadress` = \'' . $ipaddress . '\' ';
+       $select_data = 'SELECT MAX(id_view) as max_id FROM `' . _DB_PREFIX_ . 'tvcmsposts_view` where `id_tvcmsposts` = ' . (int) $blogid . ' AND `ipadress` = \'' . pSQL($ipaddress) . '\' ';
        $ans = Db::getInstance()->executeS($select_data);

        if (1 > $ans[0]['max_id']) {
            $dataquery = 'INSERT INTO `' . _DB_PREFIX_ . 'tvcmsposts_view`
                                SET 
-                                   `id_tvcmsposts` = ' . $blogid . ',
+                                   `id_tvcmsposts` = ' . (int) $blogid . ',
-                                    ipadress = \'' . $ipaddress . '\'';
+                                    ipadress = \'' . pSQL($ipaddress) . '\'';
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **tvcmsblog**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* These HTTP headers are not supposed to be used on a final application, since they should be used only if `REMOTE_ADDR` is allowed with modules like mod_remoteip for Apache2, so you should auto-delete them if you are not behind a well setup load-balancer or reverse proxy.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-02-10 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-02-10 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-02-15 | The author provided a patch, but it still contains all critical vulnerabilities. |
| 2023-04-13 | Recontact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-04-13 | Request a CVE ID |
| 2023-05-19 | Author provide patch |
| 2023-08-15 | Received CVE ID |
| 2023-08-24 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/themes-electronique-high-tech/29992-electron-mega-electronique-high-tech-store.html)
* [Author product page](https://themevolty.com/electron-mega-electronic-store)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-39650)
