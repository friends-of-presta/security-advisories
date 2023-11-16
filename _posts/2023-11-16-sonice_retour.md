---
layout: post
title: "[CVE-2023-45382] Improper Limitation of a Pathname to a Restricted Directory in Common-Services - SoNice Retour module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,sonice_retour"
severity: "high (7.5), GDPR violation"
---

In the module "SoNice Retour" (sonice_retour) up to version 2.1.0 from Common-Services for PrestaShop, a guest can download personal information without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2023-45382](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45382)
* **Published at**: 2023-11-16
* **Platform**: PrestaShop
* **Product**: sonice_retour
* **Impacted release**: <= 2.1.0 (2.2.20 fixed the vulnerability)
* **Product author**: Common-Services
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5)

## Description

Due to a lack of permissions control and a lack of control in the path name construction, a guest can perform a path traversal to view all files on the information system.

Note : We are forced to tag it as a high gravity due to the CWE type 22 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds of admin's ajax scripts of modules due to [this](https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247)

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
* Exfiltrate all modules with all versions to facilitate pentesting
* Stealing table_prefix to greatly facilitate SQL injections for kiddies who don't know how to exploit DBMS design's vulnerabilities or steal database access to login in exposed PHPMyAdmin/Adminer/etc.
* Bypass WAF / htaccess restrictions to read forbidden files (such as logs on predictable paths of banks's modules inside /var/log/)

## Patch from 2.1.0

```diff
--- 2.1.0/modules/sonice_retour/functions/downloadLabel.php
+++ XXXXX/modules/sonice_retour/functions/downloadLabel.php
    public function action()
    {
-       $file = $_REQUEST['file'];
+       $file = basename($_REQUEST['file']);
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **sonice_retour**.
* You should consider restricting the access of modules/sonice_retour/ to a whitelist
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop

## Timeline

| Date | Action |
|--|--|
| Q3 2022 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| Q3 2022 | Ask developpers concerned to report it to author |
| 2023-05-19 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-05-19 | Request a CVE ID |
| 2023-05-31 | Author provide a patch that fix the leak |
| 2023-10-12 | Received CVE ID |
| 2023-11-16 | Publish this security advisory |

## Links

* [Author website](https://common-services.com/fr/home-fr/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45382)
