---
layout: post
title: "[CVE-2024-25839] Exposure of Sensitive Information to an Unauthorized Actor in Webbax - Super Newsletter module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,supernewsletter"
severity: "medium (7.5), GDPR violation"
---

In the module "Super Newsletter" (supernewsletter) up to version 1.4.21 (DANGER : all versions) from Webbax for PrestaShop, a guest can access to a secret of the PrestaShop.

## Summary

* **CVE ID**: [CVE-2024-25839](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25839)
* **Published at**: 2024-02-29
* **Platform**: PrestaShop
* **Product**: supernewsletter
* **Impacted release**: <= 1.4.21 (DANGER : all versions and author discontinue support)
* **Product author**: Webbax
* **Weakness**: [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
* **Severity**: medium (7.5), GDPR violation

## Description

Due to the use of a secret on the ecosystem PrestaShop, a guest can access hundreds of scripts on the PrestaShop ecosystem protected by this secret including modules which permit export of customers database.

**WARNING** : This module is obsolete and must be deleted since author discontinue support.

Note : We are forced to tag it as a high gravity due to the CWE type 200 but be warned that on our ecosystem, it must be considered critical since it unlocks hundreds admin's ajax script of modules due to [this](https://github.com/PrestaShop/PrestaShop/blob/6c05518b807d014ee8edb811041e3de232520c28/classes/Tools.php#L1247)

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

* Access scripts including admin scripts protected by token 

## Proof of concept

1. Register to the newsletter on the impacted website
2. Extract the secret COOKIE_KEY from newsletters received
3. Use it to unlock hundreds of scripts protected by token on the ecosystem including sensitives one which permit export of customers database.

## Patch from 1.4.21

```diff
--- 1.4.21/modules/supernewsletter/front_generate_newsletter.php
+++ XXXXXX/modules/supernewsletter/front_generate_newsletter.php
@@ -82,7 +82,7 @@ if($token==md5($id_supernewsletter_conte

     // tracking stats - open newsletter ?
     if($see_online!=1){
-        $html.='<img src="'.$Shop->getBaseURL().'modules/supernewsletter/front_stats.php?id_supernewsletter_content='.$id_supernewsletter_content.'&preview='.$preview.'&stats_type=open&token='._COOKIE_KEY_.'" style="height:1px;width:1px">';
+        $html.='<img src="'.$Shop->getBaseURL().'modules/supernewsletter/front_stats.php?id_supernewsletter_content='.$id_supernewsletter_content.'&preview='.$preview.'&stats_type=open&token='.Tools::encrypt('supernewsletter').'" style="height:1px;width:1px">';
     }

     // preview ?
@@ -114,7 +114,7 @@ if($token==md5($id_supernewsletter_conte
        </table>';
     }

-    $base_special_link = $Shop->getBaseURL().'modules/supernewsletter/front_stats.php?id_supernewsletter_content='.$id_supernewsletter_content.'&id_lang='.$id_lang.'&preview='.$preview.'&stats_type=special_link&token='._COOKIE_KEY_;
+    $base_special_link = $Shop->getBaseURL().'modules/supernewsletter/front_stats.php?id_supernewsletter_content='.$id_supernewsletter_content.'&id_lang='.$id_lang.'&preview='.$preview.'&stats_type=special_link&token='.Tools::encrypt('supernewsletter');

     // see online newsletter
     $url_newsletter = urlencode($Shop->getBaseURL().'modules/supernewsletter/front_generate_newsletter.php?id_supernewsletter_content='.$id_supernewsletter_content.'&id_lang='.$id_lang.'&preview=0&see_online=1&token='.md5($id_supernewsletter_content));
@@ -253,7 +253,7 @@ if($token==md5($id_supernewsletter_conte
                 $name = Tools::substr($name,0,$SupernewsletterTemplate->product_title_len).'...';
              }

-             $link_product = $Shop->getBaseURL().'modules/supernewsletter/front_stats.php?id_supernewsletter_content='.$id_supernewsletter_content.'&id_product='.$p['id_product'].'&id_product_attribute='.$p['id_product_attribute'].'&id_lang='.$id_lang.'&preview='.$preview.'&stats_type=product&token='._COOKIE_KEY_;
+             $link_product = $Shop->getBaseURL().'modules/supernewsletter/front_stats.php?id_supernewsletter_content='.$id_supernewsletter_content.'&id_product='.$p['id_product'].'&id_product_attribute='.$p['id_product_attribute'].'&id_lang='.$id_lang.'&preview='.$preview.'&stats_type=product&token='.Tools::encrypt('supernewsletter');
              $id_unique_random = uniqid();

              $css_td_first_product = '';
@@ -428,7 +428,7 @@ if($token==md5($id_supernewsletter_conte
     </td></tr></table>';

     // unsubscribe
-    $html .= '<table style="width:100%;background-color:'.$SupernewsletterTemplate->bg_newsletter.';padding-bottom:5px;"><tr><td style="text-align:center;'.$css_font_family.';"><a href="'.$base_special_link.'&link_type=unsubscribe&link_redirect='.urlencode($Shop->getBaseURL().'modules/supernewsletter/front_unsubscribe.php?id_supernewsletter_content='.$SupernewsletterContent->id.'&token='._COOKIE_KEY_).'" target="_blank" style="color:'.$SupernewsletterTemplate->col_links_hf.';font-size:'.$SupernewsletterTemplate->size_links_hf.'px">'.$Supernewsletter->l('Cliquez ici pour vous désinscrire',$filename).'</a><td></tr></table>';
+    $html .= '<table style="width:100%;background-color:'.$SupernewsletterTemplate->bg_newsletter.';padding-bottom:5px;"><tr><td style="text-align:center;'.$css_font_family.';"><a href="'.$base_special_link.'&link_type=unsubscribe&link_redirect='.urlencode($Shop->getBaseURL().'modules/supernewsletter/front_unsubscribe.php?id_supernewsletter_content='.$SupernewsletterContent->id.'&token='.Tools::encrypt('supernewsletter')).'" target="_blank" style="color:'.$SupernewsletterTemplate->col_links_hf.';font-size:'.$SupernewsletterTemplate->size_links_hf.'px">'.$Supernewsletter->l('Cliquez ici pour vous désinscrire',$filename).'</a><td></tr></table>';

 }else{
     $html.=$Supernewsletter->l('Hack : jeton incorrect',$filename);
```

```diff
--- 1.4.21/modules/supernewsletter/front_stats.php
+++ XXXXXX/modules/supernewsletter/front_stats.php
-if($token!==_COOKIE_KEY_){die('Error : bad token');}
+if(empty($token) || $token != Tools::encrypt('supernewsletter')){die('Error : bad token');}
````

```diff
--- 1.4.21/modules/supernewsletter/front_unsubscribe.php
+++ XXXXXX/modules/supernewsletter/front_unsubscribe.php
-if($token!=_COOKIE_KEY_){die('Error : bad token');}
+if(empty($token) || $token != Tools::encrypt('supernewsletter')){die('Error : bad token');}
````

```diff
--- 1.4.21/modules/supernewsletter/admin_cron.php
+++ XXXXXX/modules/supernewsletter/admin_cron.php
-    <img src="'.$this->_path.'views/img/script_link.png" /> <span class="label_url_cron">'.$this->l('URL CRON',$page_name).'</span> : <span class="url_cron">'.$Shop->getBaseURL().'modules/'.$this->name.'/front_cron_send.php?identifier=date&identifier_value=date&emails_pack=unlimited&id_shop='.$this->context->shop->id.'&token='._COOKIE_KEY_.'</span><br/>
+    <img src="'.$this->_path.'views/img/script_link.png" /> <span class="label_url_cron">'.$this->l('URL CRON',$page_name).'</span> : <span class="url_cron">'.$Shop->getBaseURL().'modules/'.$this->name.'/front_cron_send.php?identifier=date&identifier_value=date&emails_pack=unlimited&id_shop='.$this->context->shop->id.'&token='.Tools::encrypt('supernewsletter').'</span><br/>
````

```diff
--- 1.4.21/modules/supernewsletter/front_cron_send.php
+++ XXXXXX/modules/supernewsletter/front_cron_send.php
-     if(Tools::getValue('token')!=_COOKIE_KEY_){die('error : token');}
+     $token = Tools::getValue('token');
+     if(empty($token) || $token != Tools::encrypt('supernewsletter')){die('Error : bad token');}
````


## Other recommendations

* It’s recommended to delete the module since support is discontinue.
* You MUST update your secret COOKIE_KEY, be warned that this will invalidate all your customers passwords and most of your tokens

## Timeline

| Date | Action |
|--|--|
| 2023-09-24 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-09-24 | Contact Author to confirm versions scope by author |
| 2023-09-24 | Author confirms version scope and decide to put offline the download page |
| 2024-02-22 | Received CVE ID |
| 2024-02-29 | Publish this security advisory |

## Links

* [Author page](https://www.webbax.ch/2017/08/30/9-modules-prestashop-gratuits-offert-par-webbax/)
* [Author page](https://shop.webbax.ch/prestashop-15-/71-module-supernewsletter-15.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-25839)
