---
layout: post
title: "[CVE-2023-30196] Improper Limitation of a Pathname to a Restricted Directory in Webbax - Sales Booster module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,salesbooster"
severity: "high (7.5), GDPR violation"
---

In the module "Sales Booster" (salesbooster) from Webbax for PrestaShop, a guest can download personal informations without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2023-30196](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30196)
* **Published at**: 2023-05-22
* **Platform**: PrestaShop
* **Product**: salesbooster
* **Impacted release**: <= 1.10.4 (1.10.5 fixed the vulnerability)
* **Product author**: Webbax
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5)

## Description

Due to predictible token and a lack of control in the path name construction, a guest can perform a path traversal to view all files on the information system.

Note : We are forced to tag it as a high gravity due to the CWE type 22 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds admin's ajax script of modules due to [this](https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247)

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

* Stealing secrets to unlock admin controllers based on ajax script
* Exfiltrate all modules with all versions to facilite pentesting
* Stealing table_prefix to greatly facilitate SQL injections for kiddies who don't know how to exploit DBMS design's vulnerabilities or steal database access to login in exposed PHPMyAdmin / Adminer / etc.
* Bypass WAF / htaccess restrictions to read forbidden files (such as logs on predictible paths of banks's modules inside /var/log/)

## Patch from 1.10.4

```diff
--- 1.10.4/modules/salesbooster/downloads/download.php
+++ 1.10.5/modules/salesbooster/downloads/download.php
...
-$file = Tools::getValue('file');
+$file = basename(Tools::getValue('file')).'.txt';
+if((strpos($file, './') === false) && substr($file,-4) == '.txt'){
...
+}
...
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **salesbooster**.
* Update the configuration SALESBOOSTER_TOKEN in your ps_configuration table with a string not predictible - **be warned that the patch provided by author still suffer of a predictible security token mecanism.**
* You should consider restricting the access of modules/salesbooster/ to a whitelist
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop

## Timeline

| Date | Action |
|--|--|
| 2023-02-25 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-02-25 | Contact Author |
| 2023-02-25 | Request a CVE ID |
| 2023-02-27 | Author confirms alert's read |
| 2023-04-24 | Received CVE ID |
| 2023-05-02 | Author publishes a new version which fix the leak |
| 2023-05-22 | Publish this security advisory |

## Links

* [Author download page](https://www.webbax.ch/2017/08/30/9-modules-prestashop-gratuits-offert-par-webbax/)
* [Usefull Author advices - French](https://www.youtube.com/watch?v=ZHerGwp0oq4&t=1855s)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-30196)
