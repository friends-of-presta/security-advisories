---
layout: post
title: "[CVE-2023-45383] Improper Limitation of a Pathname to a Restricted Directory in Common-Services - Sonice Etiquetage module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 ecommerce.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,sonice_etiquetage"
severity: "high (7.5), GDPR violation"
---

In the module "SoNice Etiquetage" (sonice_etiquetage) up to version 2.5.9 from Common-Services for PrestaShop, a guest can download personal informations without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2023-45383](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45383)
* **Published at**: 2023-10-17
* **Platform**: PrestaShop
* **Product**: sonice_etiquetage
* **Impacted release**: <= 2.5.9 (2.6.1 fixed the vulnerability)
* **Product author**: Common-Services
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5)

## Description

Due to a lack of permissions control and a lack of control in the path name construction, a guest can perform a path traversal to view all files on the information system.

Note : We are forced to tag it as a high gravity due to the CWE type 22 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds admin's ajax script of modules due to [this](https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247)

**WARNING** : Be informed that this vulnerability is actively exploited.

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
* Stealing table_prefix to greatly facilitate SQL injections for kiddies who don't know how to exploit DBMS design's vulnerabilities or steal database access to login in exposed PHPMyAdmin/Adminer/etc.
* Bypass WAF / htaccess restrictions to read forbidden files (such as logs on predictable paths of banks's modules inside /var/log/)

## Patch from 2.5.9

```diff
--- 2.5.9/modules/sonice_etiquetage/functions/download_label.php
+++ XXXXX/modules/sonice_etiquetage/functions/download_label.php
 public function action()
    {
-       $file = Tools::getValue('file');
+       $file = basename(Tools::getValue('file'));
```


```diff
--- 2.5.9/modules/sonice_etiquetage/functions/download_label_img.php
+++ XXXXX/modules/sonice_etiquetage/functions/download_label_img.php
    public function action()
    {
-       $file = $_REQUEST['file'];
+       $file = basename($_REQUEST['file']);
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **sonice_etiquetage**.
* You should consider restricting the access of the pattern modules/sonice_etiquetage/functions/download to a whitelist
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop

## Timeline

| Date | Action |
|--|--|
| 2022-09-19 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2022-09-19 | Ask developpers concerned to report it to author |
| 2023-05-19 | Contact PrestaShop Addons security Team to confirm versions scope by author |
| 2023-05-19 | PrestaShop Addons security Team confirm versions scope by author |
| 2023-05-19 | Request a CVE ID |
| 2023-05-31 | Author provide patch |
| 2023-10-11 | Received CVE ID |
| 2023-10-17 | Publish this security advisory |

## Links

* [Author website](https://common-services.com/fr/home-fr/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45383)
