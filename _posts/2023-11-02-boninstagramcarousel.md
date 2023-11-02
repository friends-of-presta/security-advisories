---
layout: post
title: "[CVE-2023-43982] Server-Side Request Forgery (SSRF) in Bon Presta - SocialFeed - Photos & Video/Reels using the Instagram API for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- Ambris.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,boninstagramcarousel"
severity: "critical (9.1)"
---

In the module "SocialFeed - Photos & Video/Reels using Instagram API" (boninstagramcarousel) up to version 6.0.0 from Bon Presta for PrestaShop, an anonymous user can perform a Server-Side Request Forgery (SSRF).

## Summary

* **CVE ID**: [CVE-2023-43982](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43982)
* **Published at**: 2023-11-02
* **Platform**: PrestaShop
* **Product**: boninstagramcarousel
* **Impacted release**: >= 5.2.1 & <= 6.0.0 (7.0.0 fixed the vulnerability)
* **Product author**: Bon Presta
* **Weakness**: [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
* **Severity**: critical (9.1)

## Description

An improper validation of the `url` parameter in the `insta_parser.php` script can be executed via a trivial HTTP call to forge Server-Side Request. 

This vulnerability can be exploited to initiate an HTTP request and get the return, for instance, use the vulnerable website as a proxy to attack other websites, exfiltrate data in files under IP restriction or perform a path traversal attack.

Since it's a design issue, we cannot provide a patch, you should consider upgrading or deleting the module.


## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Possible malicious usage

* Attack other websites via the vulnerability
* Bypass WAF/.htaccess restrictions
* Perform a path traversal attack using the wrapper : file://

## Other recommendations

* It’s recommended to upgrade the module to its latest version
* You should restrict access to modules/boninstagramcarousell/controllers/back/ to a given whitelist
* Activate OWASP 931's rules on your WAF (Web application firewall), be warned that you will probably break your frontoffice and your backoffice and you will need to pre-configure some bypasses against these sets of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-08-04 | Issue discovered during a code review by [Ambris Informatique](https://ambris.com/) and [TouchWeb](https://www.touchweb.fr/) |
| 2023-08-04 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-08-21 | PrestaShop Addons security Team confirm versions scope by author |
| 2023-09-21 | Request a CVE ID |
| 2023-09-28 | Received CVE ID |
| 2023-11-02 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/sliders-galleries/27475-socialfeed-photos-video-reels-using-instagram-api.html)
* [National Vulnerability Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43982)

