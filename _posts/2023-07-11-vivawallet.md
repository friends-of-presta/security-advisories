---
layout: post
title: "[CVE-2023-26861] Improper neutralization of several SQL parameters in vivawallet module for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,vivawallet"
severity: "critical (9.8)"
---

The deprecated module "vivawallet" (name of the directory) edited by Viva Wallet prior to 1.7.9 for PrestaShop has several SQL injections.

## Summary

* **CVE ID**: [CVE-2023-26861](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-26861)
* **Published at**: 2023-07-11
* **Advisory source**: Friends-Of-Presta.org
* **Vendor**: PrestaShop
* **Product**: vivawallet
* **Impacted release**: < 1.7.9
* **Product author**: Viva Wallet
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

The deprecated PrestaShop [module VivaWallet removed on github](https://github.com/VivaPayments/API/commit/c1169680508c6e144d3e102ebdb257612e4cd84a) on Oct 19, 2022 has sensitive SQL calls that can be exploited to manage a blind SQL injection on front controller fail.php, success.php and webhook.php.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller’s path during the exploit so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see “POST /” inside your conventional frontend logs**. Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: low
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Copy/paste data from sensitive tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patches

Advice: Remove vivawallet and install vivawalletsmartcheckout instead.


```diff
--- a/vivawallet/controllers/front/fail.php
+++ b/vivawallet/controllers/front/fail.php
@@ -9,7 +9,7 @@ class VivawalletFailModuleFrontController
   
 	  if(isset($_GET['s']) && $_GET['s']!=''){
 
-	  $OrderCode = stripslashes($_GET['s']);
+	  $OrderCode = pSQL($_GET['s']);
 	  
 	  $check_query = "select * from vivawallet_data where OrderCode='".$OrderCode."' ORDER BY id DESC";
 	  $check = Db::getInstance()->executeS($check_query, $array = true, $use_cache = 0);

--- a/vivawallet/controllers/front/success.php
+++ b/vivawallet/controllers/front/success.php
@@ -9,7 +9,7 @@ class VivawalletSuccessModuleFrontContro
 	
 	  if(isset($_GET['s']) && $_GET['s']!=''){
 	  $errors = '';
-	  $OrderCode = stripslashes($_GET['s']);
+	  $OrderCode = pSQL($_GET['s']);
 	  
 	  $check_query = "select * from vivawallet_data where OrderCode='".$OrderCode."' ORDER BY id DESC";
 	  $check = Db::getInstance()->executeS($check_query, $array = true, $use_cache = 0);

--- a/vivawallet/controllers/front/webhook.php
+++ b/vivawallet/controllers/front/webhook.php
@@ -65,7 +65,7 @@ class VivawalletWebhookModuleFrontContro
 		$OrderCode = $resultObj->EventData->OrderCode;
 		$TransactionId = $resultObj->EventData->TransactionId;
 		
-		$check_query = "select * from vivawallet_data where OrderCode='".$OrderCode."' ORDER BY id DESC";
+		$check_query = "select * from vivawallet_data where OrderCode='".pSQL($OrderCode)."' ORDER BY id DESC";
 	    $check = Db::getInstance()->executeS($transtat_query, $array = true, $use_cache = 0);
 	    $oid = $transtat[0]['ref'];
 		
@@ -106,11 +106,11 @@ class VivawalletWebhookModuleFrontContro
 	    $currency = $this->context->currency;
 	    $total = (float)$cart->getOrderTotal(true, Cart::BOTH);
 	
-		  $transtat_query = "select * from vivawallet_data where OrderCode='".$OrderCode."' ORDER BY id DESC";
+		  $transtat_query = "select * from vivawallet_data where OrderCode='".pSQL($OrderCode)."' ORDER BY id DESC";
 		  $transtat = Db::getInstance()->executeS($transtat_query, $array = true, $use_cache = 0);
 		  
 		  if($transtat[0]['order_state']=='I' && $StatusId=='F'){
-		  $update_query = "update vivawallet_data set order_state='P' where OrderCode='".$OrderCode."'";
+		  $update_query = "update vivawallet_data set order_state='P' where OrderCode='".pSQL($OrderCode)."'";
 		  $update = Db::getInstance()->execute($update_query);
 		
 		  $details = array(
```

## Other recommandations

* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.


## Timeline

| Date | Action |
|--|--|
| 2023-02-12 | Vulnerabity discovered during an audit by [Touch Web](https://www.touchweb.fr/) and [202 ecommerce](https://www.202-ecommerce.com/) |
| 2023-02-23 | Contact the author |
| 2023-02-23 | Response of the author that a new module replace the impacted module |
| 2023-02-25 | Inform the author that a CVE ID is requested |
| 2023-03-17 | Propose a delay of 90 days before disclosing the CVE |
| 2023-03-17 | Request a CVE ID |
| 2023-07-17 | Publication of this CVE |


## Links

* [GitHub addons product page](https://github.com/VivaPayments/API/)
* [Viva Wallet developper page](https://developer.vivawallet.com/plugins/)
* [Viva Wallet lastest updated module](https://addons.prestashop.com/fr/paiement/89363-viva-wallet-smart-checkout.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-26861)

