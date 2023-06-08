---
layout: post
title: "[CVE-2023-30197] Improper Limitation of a Pathname to a Restricted Directory in Webbax - My inventory module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,myinventory"
severity: "high (7.5), GDPR violation"
---

In the module "My inventory" (myinventory) from Webbax for PrestaShop, a guest can download personal informations without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2023-30197](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30197)
* **Published at**: 2023-05-30
* **Platform**: PrestaShop
* **Product**: myinventory
* **Impacted release**: <= 1.6.6 (1.6.7 fixed the vulnerability)
* **Product author**: Webbax
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5), GDPR violation

## Description

Due to a lack of permissions's control and a lack of control in the path name's construction, a guest can perform a path traversal to view all files on the information system.

Note : We are forced to tag it as a medium gravity due to the CWE type 22 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds admin's ajax script of modules  due to [this](https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247)


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
* Exfiltrate all modules with all versions to facilited pentesting
* Stealing table_prefix to greatly facilitate SQL injections for kiddies who don't known how exploit DBMS design's vulnerabilities or stealing database access to login in exposed PHPMyAdmin/Adminer/etc.
* Bypass WAF / htaccess restrictions to read forbidden files (such as logs on predictible paths of banks's modules inside /var/log/)


## Patch from 1.6.6

```diff
--- 1.6.6/modules/myinventory/downloads/download.php
+++ 1.6.7/modules/myinventory/downloads/download.php
- $file = Tools::getValue('file');
+ $file = basename(Tools::getValue('file')).'.csv';

+if((strpos($file, './') === false) && substr($file,-4) == '.csv'){
...
+}
```

## Other recommandations

* You should consider to restrict the access of modules/myinventory/ to a whitelist or delete the module
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your Prestashop

## Timeline

| Date | Action |
|--|--|
| 2023-02-25 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-02-25 | Contact Author |
| 2023-02-27 | Author confirm alert's read |
| 2023-04-24 | Received CVE ID |
| 2023-05-02 | Author publish a new version which fix the leak |
| 2023-05-30 | Publish this security advisory |

## Links

* [Author download page](https://www.webbax.ch/2017/08/30/9-modules-prestashop-gratuits-offert-par-webbax/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-30197)
