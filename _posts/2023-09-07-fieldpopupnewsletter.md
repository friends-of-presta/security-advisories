---
layout: post
title: "[CVE-2023-39676] XSS in FieldPopupNewsletter Prestashop Module"
categories: modules
author:
- Sorcery Ltd
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,fieldpopupnewsletter"
severity: "medium (6.1)"
---

An XSS was found within the FieldPopupNewsletter module, developed by [FieldThemes](https://themeforest.net/user/fieldthemes), for the popular ecommerce platform Prestashop.

## Summary

* **CVE ID**: [CVE-2023-39676](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39676)
* **Published at**: 2023-09-07
* **Discovery credit**: [Sorcery](https://sorcery.ie/)
* **Platform**: PrestaShop
* **Product**: fieldpopupnewsletter
* **Impacted release**: < 1.0.1 ?
* **Product author**: [FieldThemes](https://themeforest.net/user/fieldthemes)
* **Weakness**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
* **Severity**: {{ page.severity }}

## Description

The module contains a file called ajax.php with the following code:

```php
$ppp = new FieldPopupNewsletter();
echo $ppp->newsletterRegistration($_POST['email']);
```

The newsletterRegistration function, called by the ajax.php file, contains code that lacks proper input validation:

```php
public function newsletterRegistration($email) {
  if (empty($email) || !Validate::isEmail($email)) {
    echo $_GET['callback'] . '(' . json_encode(array('<p class="alert alert-danger">' . $this->l('Invalid email address.') . '</p>')) . ')';
    return;
  }
```

The callback GET parameter is printed to the page without sanitization which makes it susceptibvle to XSS. One might think the fact a POST parameter is used might mitigate this vulnerability but closer reading reveals this works when `$_POST['email']` isn’t set.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: Required
* **Scope**: unchanged
* **Confidentiality**: low
* **Integrity**: low
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

## Proof of Concept

As a demonstration of the vulnerability, an attacker can craft a malicious URL, like the one shown below, to execute arbitrary JavaScript code on the target user’s browser:

```
http://localhost/modules/fieldpopupnewsletter/ajax.php?callback=%3Cscript%3Ealert(0)%3C/script%3E
```

## Patch

```diff
--- a/modules/fieldpopupnewsletter/fieldpopupnewsletter.php
+++ b/modules/fieldpopupnewsletter/fieldpopupnewsletter.php
@@ -684,0 +685,3 @@ class FieldPopupNewsletter extends Module
+               if (isset($_GET['callback']) && !Validate::isCleanHtml($_GET['callback'])) {
+                       return;
+               }
```

## Other recommendations

XSS vulnerabilities are serious security risks that can lead to unauthorized access, data theft, and other malicious activities. In the case of the FieldPopupNewsletter module, a lack of input validation exposes users to potential attacks.

We strongly advise users of this module to update to the latest patched version, which should address the XSS vulnerability.

## Timeline

| Date | Action |
|--|--|
|10/07/2023 | Issue discovered during a pentest |
|12/07/2023 | Reported issue to FieldThemes |
|29/07/2023 | Requested CVE from MITRE |
|28/08/2023 | Number CVE-2023-39676 assigned |
|31/08/2023 | Patch released |
|07/09/2023 | Blog post and [nuclei template](https://github.com/projectdiscovery/nuclei-templates/pull/8173) released |

## Links

* [References](https://blog.sorcery.ie/posts/fieldpopupnewsletter_xss/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-39676)
* [Editor](https://themeforest.net/user/fieldthemes)
