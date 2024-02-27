---
layout: post
title: "[CVE-2024-25841] Improper Neutralization of Input During Web Page Generation in Common-Services - So Flexibilite module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,soflexibilite"
severity: "critical (9.0)"
---

In the module "So Flexibilite" (soflexibilite) up to version 4.1.14 from Common-Services for PrestaShop, a guest (authenticated customer) can perform XSS injection of type 2 (Stored XSS) from FRONT to BACK (F2B) within the funnel order in affected versions.

Note: To succeed in this exploit, the red team needs to pay to convert a cart into a valid order with a SoColissimo carrier, which allows you to enter a custom email such as "Point Relay" and requires the administrator to go to the order management page in its backoffice. To be exploited, you will probably need interaction with the shop's owner to update the custom email given for SoColissimo after you pay.

Since there is a deletion of hooks with PS 1.7.7+, it does not concern all installations : 
- Versions from 4.0.X to 4.1.6 are only vulnerable on PS 1.7.6- (including probably PS 1.6 - to confirm) since hookDisplayAdminOrderContentShip no longer exist on PS 1.7.7+ (https://devdocs.prestashop-project.org/1.7/modules/core-updates/1.7.7/#modified-hooks)
- Versions from 4.1.7 and above are vulnerable on all PS versions (at least 1.7+ - to confirm on PS 1.6)

## Summary

* **CVE ID**: [CVE-2024-25841](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25841)
* **Published at**: 2024-02-27
* **Platform**: PrestaShop
* **Product**: soflexibilite
* **Impacted release**: <= 4.1.14 (4.1.26 fixed the vulnerability)
* **Product author**: Common-Services
* **Weakness**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
* **Severity**: critical (9.0)

## Description
As with all XSS type 2 (Stored XSS) F2B, there are two steps and a prerequisite.

1/3 : The method `SoFlexibiliteDeliveryInfo::save()` does not properly clean the parameter `ceemail`. pSQL (herited from ObjectModel with configuration self::TYPE_STRING with no validator setup) is useless against XSS in category 2.
2/3 : The field `ceemail` within table colissimo_delivery_info suffers from a type varchar(64), which is large enough to allow dangerous XSS payloads.
3/3 : The output in the backoffice is not escaped in the related smarty template that uses it.

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

## Possible malicious usage

* Unlock design's vulnerability, see this : https://friends-of-presta.github.io/security-advisories/modules/2023/02/07/stored-xss.html

## Patch from 4.1.14

```diff
--- 4.1.14/modules/soflexibilite/views/templates/admin/orders/displayadminordercontentship.tpl
+++ 4.1.26/modules/soflexibilite/views/templates/admin/orders/displayadminordercontentship.tpl
...
                </span>
-               <input type="email" class="form-control ceemail" placeholder="{l s='Email' mod='soflexibilite'}" aria-describedby="sf_sumpup_email" value="{$sf_delivery_info->ceemail}">
+               <input type="email" class="form-control ceemail" placeholder="{l s='Email' mod='soflexibilite'}" aria-describedby="sf_sumpup_email" value="{$sf_delivery_info->ceemail|escape:'htmlall':'UTF-8'}">
            </div>
```


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **soflexibilite**.
* Systematically escape characters ' " < and > by replacing them with HTML entities and applying strip_tags - Smarty and Twig provide auto-escape filters :
  - Smarty: `{$value.comment|escape:'html':'UTF-8'}`
  - Twig:`{% raw %}{{value.comment|e}}{% endraw %}`
* Limit to the strict minimum the length's value in database - a database field that allows 10 characters (`varchar(10)`) is far less dangerous than a field that allows 40+ characters (use cases that can exploit fragmented XSS payloads are very rare).
* Configure CSP headers (content security policies) by listing external domains allowed to load assets (such as js files) or being called in XHR transactions (Ajax).
* If applicable: check against all your frontoffice's uploaders, uploading files that will be served by your server that mime type application/javascript (like every .js natively) must be strictly forbidden as it must be considered as dangerous as PHP files.
* Activate OWASP 941's rules on your WAF (Web application firewall) - be warned that you will probably break your frontoffice/backoffice and you will need to preconfigure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-02-27 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-02-27 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-09-14 | Author provide a patch |
| 2024-01-24 | PrestaShop Addons security Team confirms version scope by author |
| 2024-02-22 | Received CVE ID |
| 2024-02-27 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/transporteurs/2704-colissimo-domicile-et-points-de-retrait.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-25841)
