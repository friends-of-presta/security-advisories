---
layout: post
title: "[CVE-2023-30200] Improper Limitation of a Pathname to a Restricted Directory in Advanced Plugins - Image: WebP, Compress, Zoom, Lazy load, Alt & More module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ultimateimagetool"
severity: "high (7.5), GDPR violation"
---

In the module "Image: WebP, Compress, Zoom, Lazy load, Alt & More" (ultimateimagetool) in versions up to 2.1.02 from Advanced Plugins for PrestaShop, a guest can download personal informations without restriction by performing a path traversal attack.

## Summary

* **CVE ID**: [CVE-2023-30200](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30200)
* **Published at**: 2023-07-20
* **Platform**: PrestaShop
* **Product**: ultimateimagetool
* **Impacted release**: <= 2.1.02 (considered to be "truly" fixed on 2.1.03 - see note below)
* **Product author**: Advanced Plugins
* **Weakness**: [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
* **Severity**: high (7.5), GDPR violation

## Description

Due to a lack of control in the path name construction, a guest can perform a path traversal to view all files on the information system.

Note : The author has deleted from its module the file that have been suffering from this leak for months, BUT did not set it to be "auto-deleted" during upgrades. Therefore, there are likely merchants out there with older versions who have updated their modules thinking they are safe. However, there is nothing safe about this since past upgrades do not auto-delete the implicated file. To ensure everyone has a "safe version", we decided to mark all versions up to 2.1.02 as impacted by this issue.

**WARNING** : We are forced to tag it as a medium gravity due to the CWE type 22 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds admin's ajax script of modules due to [the behaviour of PrestaShop core](https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247) Tools::hash() method


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
* Bypass WAF / htaccess restrictions to read forbidden files (such as logs on predictible paths of banks's modules inside /var/log/)

## Patch from 1.5.96

```diff
--- 1.5.96/modules/ultimateimagetool/image.php
+++ XXXXXX/modules/ultimateimagetool/image.php
-	$src = urldecode($_GET['image']);
+	$src = basename(urldecode($_GET['image']));
```

Be warned that this fix is perfectible. See recommendations below.

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **ultimateimagetool**.
* You should consider restricting the access of modules/ultimateimagetool/images.php to a whitelist
* NEVER expose a PHPMyAdmin / Adminer / etc without, at least, a htpasswd
* Activate OWASP 930's rules on your WAF (Web application firewall) and adjust it for your PrestaShop

## Timeline

| Date | Action |
|--|--|
| 2023-03-29 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-03-29 | Contact PrestaShop Addons security Team to confirm versions scope by author  |
| 2023-04-01 | Request CVE ID |
| 2023-04-18 | PrestaShop Addons confirms versions scopes |
| 2023-04-18 | Author provide patch |
| 2023-04-24 | Received CVE ID |
| 2023-07-20 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/visuels-produits/27669-image-webp-compression-regeneration.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-30200)
