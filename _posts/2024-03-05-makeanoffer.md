---
layout: post
title: "[CVE-2024-25849] Improper neutralization of SQL parameter in PrestaToolKit - Make an offer module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
meta: "CVE,PrestaShop,makeanoffer"
severity: "critical (9.8)"
---

In the module "Make an offer" (makeanoffer) up to version 1.7.1 from PrestaToolKit for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2024-25849](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25849)
* **Published at**: 2024-03-05
* **Platform**: PrestaShop
* **Product**: makeanoffer
* **Impacted release**: <= 1.7.1 (1.7.2 fixed the vulnerability)
* **Product author**: PrestaToolKit
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Methods `MakeOffers::checkUserExistingOffer()` and `MakeOffers::addUserOffer()` have sensitives SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

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
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admin's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch from 1.7.1

```diff
--- 1.7.1/modules/makeanoffer/model/MakeOffersModel.php
+++ 1.7.2/modules/makeanoffer/model/MakeOffersModel.php
	public function checkUserExistingOffer($id_product, $email, $cid)
	{
		$result = Db::getInstance()->executeS('
		SELECT `id_makeanoffer`
		FROM `'._DB_PREFIX_.'makeanoffer`
		WHERE `id_product` = '.(int)$id_product.'
-		AND id_combination = '.(int)$cid.' AND email = "'.$email.'"');
+		AND id_combination = '.(int)$cid.' AND email = "'.pSQL($email).'"');
		return count($result);
	}
	
	public function addUserOffer($id_product, $email, $cid, $name, $phone, $message, $amount, $customer_id, $real_price, $id_currency)
	{
		empty($message) ? $message = 'empty' : $message;
		empty($name) ? $name = 'no name' : $name;
		empty($phone) ? $phone = 'empty' : $phone;
		Db::getInstance()->execute('INSERT INTO '._DB_PREFIX_.'makeanoffer (id_product, email, id_combination, status, name, phone, message, amount_offer, customer_id, original_price, id_curr)
-			VALUES('.(int)$id_product.', "'.(string)$email.'", '.(int)$cid.', 0, "'.(string)$name.'", "'.(string)$phone.'", "'.(string)$message.'", "'.(string)$amount.'", '.(int)$customer_id.', "'.(string)$real_price.'", '.(int)$id_currency.')
+			VALUES('.(int)$id_product.', "'.pSQL($email).'", '.(int)$cid.', 0, "'.pSQL($name).'", "'.pSQL($phone).'", "'.pSQL($message).'", "'.pSQL($amount).'", '.(int)$customer_id.', "'.pSQL($real_price).'", '.(int)$id_currency.')
		');
		$last_id = (int)Db::getInstance()->Insert_ID();
		return $last_id;
	}
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **makeanoffer**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2024-01-15 | Issue discovered during a code review by [TouchWeb](https://www.touchweb.fr) |
| 2024-01-15 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2024-01-17 | PrestaShop Addons security Team confirms version scope by author |
| 2024-01-23 | Author provide a patch |
| 2024-02-22 | Received CVE ID |
| 2024-03-05 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/en/price-management/19507-make-an-offer.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-25849)
