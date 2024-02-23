---
layout: post
title: "[CVE-2023-45378] Improper neutralization of SQL parameter in HDclic - PrestaBlog module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- Creabilis.com
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,prestablog"
severity: "critical (9.8)"
---

In the module "PrestaBlog" (prestablog) up to version 4.4.7 from HDclic for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-45378](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45378)
* **Published at**: 2023-10-26
* **Platform**: PrestaShop
* **Product**: prestablog
* **Impacted release**: <= 4.4.7  (considered to be "truly" fixed on 4.4.8 - see note below)
* **Product author**: HDclic
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The script ajax slider_positions.php has a sensitive SQL call that can be executed with a trivial http call and exploited to forge a SQL injection.

Note : The author has deleted from its module the files that have been suffering from critical vulnerabilities for months, BUT did not set them to be "auto-deleted" during upgrades. Therefore, there are likely merchants out there with older versions who have updated their modules, thinking they are safe. However, there is nothing safe about this, since past upgrades did not auto-delete the implicated files. To ensure everyone has a "safe version", we decided to mark all versions up to 4.4.7 as impacted by this issue.

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


## Patch from 4.4.3

```diff
--- 4.4.3/modules/prestablog/slider_position.php
+++ 4.4.8/modules/prestablog/slider_position.php
    foreach ($slides as $position => $id_slide) {
        $res = Db::getInstance()->execute(
        '
      UPDATE `'._DB_PREFIX_.'prestablog_slide_lang` SET `position` = '.(int)$position.'
-     WHERE `id_slide` = '.(int)$id_slide.' AND `id_lang` = '.Tools::getValue('languesup')
+     WHERE `id_slide` = '.(int)$id_slide.' AND `id_lang` = '.(int) Tools::getValue('languesup')
    );
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **prestablog**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2022-09-08 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2022-09-08 | Creabilis contact author to fix the vulnerability |
| 2022-09-09 | Author provide a patch |
| 2023-05-19 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-05-19 | Request a CVE ID |
| 2023-05-25 | PrestaShop Addons security Team confirm versions scope by author |
| 2023-10-11 | Received CVE ID |
| 2023-10-26 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/blog-forum-actualites/4731-prestablog-un-blog-professionnel-pour-votre-boutique.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-45378)
