---
layout: post
title: "[CVE-2023-27844] Improper neutralization of SQL parameter in leurlrewrite for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,leurlrewrite"
severity: "critical (9.8)"
---

In the module "LitExtension Url Plugin" (leurlrewrite) for PrestaShop, an attacker can perform SQL injection up to 1.0. Even though the module has been patched in version 1.0, the version number was not incremented at the time. We consider the issue resolved in versions after 1.0.

## Summary

* **CVE ID**: [CVE-2023-27844](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27844)
* **Published at**: 2023-04-13
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: leurlrewrite
* **Impacted release**: < 1.0
* **Product author**: LitExtension
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

A sensitive SQL call the overrided class `Dispatcher::getController()` can be executed with a trivial http call and exploited to forge a blind SQL injection through by calling a not found page.


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
* Display sensitives tables to front-office to unlock potential admin’s ajax scripts of modules protected by token on the ecosystem

## Patch

*IMPORTANT*: apply the patch and reset the module or update the override/classes/Dispatcher.php of the PrestaShop manually.

```diff
--- a/modules/leurlrewrite/override/classes/Dispatcher.php
+++ b/modules/leurlrewrite/override/classes/Dispatcher.php
@@ -88,7 +88,7 @@ class Dispatcher extends DispatcherCore {
                if ($controller == 'pagenotfound' || $controller == '404' || $controller === false) {
             //$url_rewrite = preg_replace('#^' . preg_quote(Context::getContext()->shop->getBaseURI(), '#') . '#i', '', $_SERVER['REQUEST_URI']);
             $url_rewrite = trim($this->request_uri, '/');
-            $results = Db::getInstance()->executeS("SELECT id_desc, type, lang_code FROM " . _DB_PREFIX_ . "lecm_rewrite WHERE link_rewrite = '" . $url_rewrite . "'");
+            $results = Db::getInstance()->executeS("SELECT id_desc, type, lang_code FROM " . _DB_PREFIX_ . "lecm_rewrite WHERE link_rewrite = '" . pSQL($url_rewrite) . "'");
             if ($results) {
                 $rewrite = array_pop($results);
                 $controller = $rewrite['type'];
```

```diff
--- a/override/classes/Dispatcher.php
+++ b/override/classes/Dispatcher.php
@@ -88,7 +88,7 @@ class Dispatcher extends DispatcherCore {
                if ($controller == 'pagenotfound' || $controller == '404' || $controller === false) {
             //$url_rewrite = preg_replace('#^' . preg_quote(Context::getContext()->shop->getBaseURI(), '#') . '#i', '', $_SERVER['REQUEST_URI']);
             $url_rewrite = trim($this->request_uri, '/');
-            $results = Db::getInstance()->executeS("SELECT id_desc, type, lang_code FROM " . _DB_PREFIX_ . "lecm_rewrite WHERE link_rewrite = '" . $url_rewrite . "'");
+            $results = Db::getInstance()->executeS("SELECT id_desc, type, lang_code FROM " . _DB_PREFIX_ . "lecm_rewrite WHERE link_rewrite = '" . pSQL($url_rewrite) . "'");
             if ($results) {
                 $rewrite = array_pop($results);
                 $controller = $rewrite['type'];
```

## Other recommendations

* It’s recommended to upgrade the module beyond 1.0.4.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix ps_ by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942’s rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline
	
| Date | Action |
|--|--|
| 2023-02-03 | Issue discovered during a code reviews by 202 ecommerce |
| 2023-02-03 | Contact the author |
| 2023-02-04 | The author publish a new package on its website |
| 2023-02-12 | Request a CVE ID |
| 2023-04-13 | Fix published on addons PrestaShop marketplace |

## Links

* [PrestaShop addons product page](https://litextension.com/migration-services/seo-urls-migrations.html#page%232)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-27844)

