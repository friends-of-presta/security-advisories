---
layout: post
title: "[CVE-2023-48925] Improper neutralization of SQL parameter in Buy Addons - Product Video, Youtube, Vimeo Tab module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,bavideotab"
severity: "critical (9.8)"
---

In the module "Product Video, Youtube, Vimeo Tab" (bavideotab) up to version 1.0.5 from Buy Addons for PrestaShop, a guest can perform SQL injection in affected versions.

## Summary

* **CVE ID**: [CVE-2023-48925]
* **Published at**: 2023-12-07
* **Platform**: PrestaShop
* **Product**: bavideotab
* **Impacted release**: <= 1.0.5 (1.0.6 fixed the vulnerability)
* **Product author**: Buy Addons
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Methods `BaVideoTabSaveVideoModuleFrontController::run()` and `BaVideoTabConfirmDeleteModuleFrontController::run()` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

**WARNING** : This exploit is actively used to deploy a webskimmer to massively steal credit cards.

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
* Copy/paste data from sensitive tables to FRONT to expose tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails


## Proof of concept


```bash
curl -v -d "fc=module&module=bavideotab&controller=confirmdelete&id=1%27;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--&id_lang=1" 'https://preprod.X/'
curl -v -d "fc=module&module=bavideotab&controller=savevideo&id_product=1%22;select(0x73656C65637420736C656570283432293B)INTO@a;prepare`b`from@a;execute`b`;--&id_lang=1" 'https://preprod.X/'
```

## Patch from 1.0.5

```diff
--- 1.0.5/modules/bavideotab/controllers/front/confirmdelete.php
+++ 1.0.6/modules/bavideotab/controllers/front/confirmdelete.php
@@ -33,8 +33,8 @@ class BaVideoTabConfirmDeleteModuleFront
     public function run()
     {
         $db = Db::getInstance(_PS_USE_SQL_SLAVE_);
-        $id_product=Tools::getValue('id');
-        $id_lang = Tools::getValue('id_lang');
+        $id_product = (int) Tools::getValue('id');
+        $id_lang = (int) Tools::getValue('id_lang');
         $id_shop=($this->context->shop->id);
         $sql="SELECT text_url FROM "._DB_PREFIX_."url_video WHERE id_product='".$id_product."'";
         $sql .= "AND id_lang='".$id_lang."' AND id_store='".$id_shop."' AND type = 1 ";

```

```diff
--- 1.0.5/modules/bavideotab/controllers/front/savevideo.php
+++ 1.0.6/modules/bavideotab/controllers/front/savevideo.php
@@ -33,14 +33,14 @@ class BaVideoTabSaveVideoModuleFrontCont
         $id_lang_default = Configuration::get('PS_LANG_DEFAULT');
         $ob_lang_default = new Language($id_lang_default);
         $name_lang_default = $ob_lang_default->name;
-        $id_shop = Tools::getValue('id_shop');
+        $id_shop = (int) Tools::getValue('id_shop');
         $name_shop = Tools::getValue('name_shop');
         $db = Db::getInstance(_PS_USE_SQL_SLAVE_);
         $url = $_SERVER['SCRIPT_FILENAME'];
         $url = rtrim($url, 'index.php');
         $languages = Language::getLanguages();
-        $type_video = Tools::getValue('type_video');
-        $id_product = Tools::getValue('id_product');
+        $type_video = (int) Tools::getValue('type_video');
+        $id_product = (int) Tools::getValue('id_product');
         $sql = 'SELECT * FROM '._DB_PREFIX_.'product_lang WHERE id_product="'.$id_product.'"';
         $show = $db->ExecuteS($sql);

@@ -91,7 +91,7 @@ class BaVideoTabSaveVideoModuleFrontCont
                         $sql = "INSERT INTO "._DB_PREFIX_."url_video ";
                         $sql .= "(id_video,id_product,id_lang,id_store,text_url,language,shop,name_product,type)";
                         $sql .= " VALUES ('','".$id_product."','".$id_lang_default."','".$id_shop."','";
-                        $sql .= "".$video_upload_default."','".$name_lang_default."','".$name_shop."','";
+                        $sql .= "".$video_upload_default."','".$name_lang_default."','".pSQL($name_shop)."','";
                         $sql .= "".$name_product."','".$type_video."')";
                         $db->query($sql);
                         $url_save_video = _PS_ROOT_DIR_.'/media/'.$id_shop."/".$id_product."/";
@@ -102,7 +102,7 @@ class BaVideoTabSaveVideoModuleFrontCont
                             $sql = "INSERT INTO "._DB_PREFIX_."url_video ";
                             $sql .= "(id_video,id_product,id_lang,id_store,text_url,language,shop,name_product,type)";
                             $sql .= " VALUES ('','".$id_product."','".$value['id_lang']."','".$id_shop."','";
-                            $sql .= "".$video_upload_default."','".$value['name']."','".$name_shop."','";
+                            $sql .= "".$video_upload_default."','".$value['name']."','".pSQL($name_shop)."','";
                             $sql .= "".$name_product."','".$type_video."')";
                             $db->query($sql);
                             $url_save_video = _PS_ROOT_DIR_.'/media/'.$id_shop."/".$id_product."/";
@@ -113,7 +113,7 @@ class BaVideoTabSaveVideoModuleFrontCont
                             $sql = "INSERT INTO "._DB_PREFIX_."url_video ";
                             $sql .= "(id_video,id_product,id_lang,id_store,text_url,language,shop,name_product,type)";
                             $sql .= " VALUES ('','".$id_product."','".$value['id_lang']."','".$id_shop."','";
-                            $sql .= "".$video_url."','".$value['name']."','".$name_shop."','";
+                            $sql .= "".$video_url."','".$value['name']."','".pSQL($name_shop)."','";
                             $sql .= "".$name_product."','".$type_video."')";
                             $db->query($sql);
                             $url_save_video = _PS_ROOT_DIR_.'/media/'.$id_shop."/".$id_product."/";
@@ -160,7 +160,7 @@ class BaVideoTabSaveVideoModuleFrontCont
                         $sql = "REPLACE INTO "._DB_PREFIX_."url_video ";
                         $sql .= "(id_video,id_product,id_lang,id_store,text_url,language,shop,name_product,type)";
                         $sql .= " VALUES ('".$id_video."','".$id_product."','".$value['id_lang']."','";
-                        $sql .= "".$id_shop."','".$video_url."','".$value['name']."','".$name_shop."','";
+                        $sql .= "".$id_shop."','".$video_url."','".$value['name']."','".pSQL($name_shop)."','";
                         $sql .= "".$name_product."','".$type_video."')";
                         $db->query($sql);
                         $url_save_video = _PS_ROOT_DIR_.'/media/'.$id_shop."/".$id_product."/";
@@ -195,7 +195,7 @@ class BaVideoTabSaveVideoModuleFrontCont
                         $sql .= "(id_video,id_product,id_store,text_url,language,shop,name_product,type,id_lang)";
                         $sql .= " VALUES ('".$id_video."','".$id_product."','".$id_shop."','";
                         $sql .= "".trim($name_url_array[$value_lang['id_lang']])."','".$value_lang['name']."','";
-                        $sql .= "".$name_shop."','".$name_product."','".$type_video."','".$value_lang['id_lang']."')";
+                        $sql .= "".pSQL($name_shop)."','".$name_product."','".$type_video."','".$value_lang['id_lang']."')";
                         $db->query($sql);
                         $ok="3";
                     }
@@ -214,7 +214,7 @@ class BaVideoTabSaveVideoModuleFrontCont
                         $sql .= "(id_video,id_product,id_store,text_url,language,shop,name_product,type,id_lang)";
                         $sql .= " VALUES ('".$id_video."','".$id_product."','".$id_shop."','";
                         $sql .= "".trim($name_url_array[$value_lang['id_lang']])."','".$value_lang['name']."','";
-                        $sql .= "".$name_shop."','".$name_product."','".$type_video."','".$value_lang['id_lang']."')";
+                        $sql .= "".pSQL($name_shop)."','".$name_product."','".$type_video."','".$value_lang['id_lang']."')";
                         $db->query($sql);
                         $ok="3";
                     } else {
@@ -230,7 +230,7 @@ class BaVideoTabSaveVideoModuleFrontCont
                         $sql .= "(id_video,id_product,id_store,text_url,language,shop,name_product,type,id_lang)";
                         $sql .= " VALUES ('".$id_video."','".$id_product."','".$id_shop."','";
                         $sql .= "".trim($name_url_array[$value_lang['id_lang']])."','".$value_lang['name']."','";
-                        $sql .= "".$name_shop."','".$name_product."','".$type_video."','".$value_lang['id_lang']."')";
+                        $sql .= "".pSQL($name_shop)."','".$name_product."','".$type_video."','".$value_lang['id_lang']."')";
                         $db->query($sql);
                         $ok="3";
                     }
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **bavideotab**.
* To help improve the security of your PrestaShop installation, we recommend upgrading to the latest version. One of the benefits of upgrading is that it will disable the use of multiquery executions (separated by semicolons). However, please be aware that this **will not protect** your shop against SQL injection attacks that use the UNION clause to steal data. Additionally, it's important to note that PrestaShop includes a function called pSQL, which includes a strip_tags function. This helps protect your shop against [Stored XSS (also known as XSS T2) of Category 1](https://security.friendsofpresta.org/modules/2023/02/07/stored-xss.html). If a pSQL function is missing, it could potentially expose your project to critical Stored XSS vulnerabilities due to edge cases. Therefore, it's crucial to ensure that all relevant functions are properly implemented and used consistently throughout your project.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skill because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-11-11 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-11-11 | Contact Author to confirm version scope by author |
| 2023-11-15 | Author confirms version scope and provide a patch |
| 2023-11-15 | Request a CVE ID |
| 2023-11-30 | Received CVE ID |
| 2023-12-07 | Publish this security advisory |

## Links

* [Author product page](https://buy-addons.com/store/prestashop/module/product-video-youtube-vimeo-tab.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-48925)
