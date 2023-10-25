---
layout: post
title: "[CVE-2023-27846] Improper neutralization of an SQL parameter in tvcmsblog module by themevolty for PrestaShop"
categories: modules
author:
- 202 ecommerce.com
- Touchweb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,tvcmsblog"
severity: "critical (9.8)"
---
​
In tvcmsblog, dependancies of the theme Electron edited by Themevolty, an attacker can perform a blind SQL injection.
​
## Summary
​
* **CVE ID**: [CVE-2023-27846](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27846)
* **Published at**: 2023-10-25
* **Advisory source**: Friends-Of-Presta.org
* **Vendor**: PrestaShop
* **Product**: tvcmsblog
* **Impacted release**: < 4.0.8 
* **Product author**: Themevolty
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)
​
## Description
​
​
Multiple sensitive SQL calls in many php classes can be executed with a trivial http call and exploited to forge a blind SQL injection throught the POST or GET submitted "rewrite", "page_type", "recordsArray" variables.
​
WARNING : Be warn that one exploit will bypass some WAF (hijacked unconventional HTTP header) in this [CVE-2023-39650](https://security.friendsofpresta.org/modules/2023/08/24/tvcmsblog.html)
​
Be warn that this module could own others vulnerabilities.
​
## CVSS base metrics
​
* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high
​
**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
​
## Possible malicious usage
​
* Remove data on the associated PrestaShop
* Copy/past datas from sensibles tables to FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijacked emails
​
​
## Patch


```diff
--- 4.0.0/modules/tvcmsblogclasses/tvcmscategoryclass.php
+++ 4.0.0_patched/modules/tvcmsblogclasses/tvcmscategoryclass.php
@@ -83,8 +83,8 @@ class TvcmsCategoryClass extends ObjectM
             return false;
         }
         $sql = 'SELECT xc.`id_tvcmscategory` FROM `' . _DB_PREFIX_ . 'tvcmscategory` xc WHERE '
-            . 'xc.`category_type` = "' . ($category_type ? $category_type : 'category')
-             . '" AND xc.active = 1 AND xc.`id_tvcmscategory` = ' . $id_category;
+            . 'xc.`category_type` = "' . ($category_type ? pSQL($category_type) : 'category')
+             . '" AND xc.active = 1 AND xc.`id_tvcmscategory` = ' . (int) $id_category;
         $rslts = Db::getInstance()->getrow($sql);
 
         return (isset($rslts['id_tvcmscategory']) && !empty($rslts['id_tvcmscategory'])) ? true : false;
@@ -96,7 +96,7 @@ class TvcmsCategoryClass extends ObjectM
             && isset($_FILES['category_img']['tmp_name'])
             && !empty($_FILES['category_img']['tmp_name'])) {
             $sql = 'SELECT * FROM `' . _DB_PREFIX_ . 'tvcmscategory` WHERE '
-             . ' `id_tvcmscategory` = ' . Tools::getValue('id_tvcmscategory');
+             . ' `id_tvcmscategory` = ' . (int) Tools::getValue('id_tvcmscategory');
             $res = Db::getInstance()->executeS($sql);
 
             if (file_exists(TVCMSBLOG_IMG_DIR . $res['category_img'])) {
@@ -105,7 +105,7 @@ class TvcmsCategoryClass extends ObjectM
             $this->category_img = TvcmsBlog::uploadMedia('category_img');
         } else {
             $sql = 'SELECT * FROM `' . _DB_PREFIX_ . 'tvcmscategory` WHERE '
-             . ' `id_tvcmscategory` = ' . Tools::getValue('id_tvcmscategory');
+             . ' `id_tvcmscategory` = ' . (int) Tools::getValue('id_tvcmscategory');
 
             $res = Db::getInstance()->executeS($sql);
             $this->category_img = $res[0]['category_img'];
@@ -204,8 +204,8 @@ class TvcmsCategoryClass extends ObjectM
             . 'xcl.`id_tvcmscategory` AND xcl.`id_lang` = ' . $id_lang . ') INNER JOIN `' . _DB_PREFIX_
              . 'tvcmscategory_shop` xcs ON (xc.`id_tvcmscategory` = xcs.`id_tvcmscategory` AND xcs.`id_shop` = '
             . $id_shop . ') ';
-        $sql .= ' WHERE xc.`category_type` = "' . ($category_type ? $category_type : 'category') . '" AND '
-            . 'xc.`id_tvcmscategory` = ' . $id_category;
+        $sql .= ' WHERE xc.`category_type` = "' . ($category_type ? pSQL($category_type) : 'category') . '" AND '
+            . 'xc.`id_tvcmscategory` = ' . (int) $id_category;
         $rslts = Db::getInstance()->getrow($sql);
 
         return $rslts;
@@ -222,8 +222,8 @@ class TvcmsCategoryClass extends ObjectM
              . 'tvcmscategory_lang` xcl ON (xc.`id_tvcmscategory` = xcl.`id_tvcmscategory` AND xcl.`id_lang` = '
             . $id_lang . ') INNER JOIN `' . _DB_PREFIX_ . 'tvcmscategory_shop` xcs ON (xc.`id_tvcmscategory` = '
             . 'xcs.`id_tvcmscategory` AND xcs.`id_shop` = ' . $id_shop . ') ';
-        $sql .= ' WHERE xc.`category_type` = "' . ($category_type ? $category_type : 'category')
-             . '" AND xcl.`link_rewrite` = "' . $rewrite . '" ';
+        $sql .= ' WHERE xc.`category_type` = "' . ($category_type ? pSQL($category_type) : 'category')
+             . '" AND xcl.`link_rewrite` = "' . pSQL($rewrite) . '" ';
         $rslts = Db::getInstance()->getrow($sql);
 
         return isset($rslts['id_tvcmscategory']) ? $rslts['id_tvcmscategory'] : null;
@@ -241,9 +241,9 @@ class TvcmsCategoryClass extends ObjectM
                     (xc.`id_tvcmscategory` = xcs.`id_tvcmscategory` '
                      . 'AND xcs.`id_shop` = ' . $id_shop . ')
                ';
-        $sql .= ' WHERE xc.`active` = 1 AND  category_type = "' . $category_type . '" ';
+        $sql .= ' WHERE xc.`active` = 1 AND  category_type = "' . pSQL($category_type) . '" ';
         if ($category_group != null) {
-            $sql .= ' AND category_group = ' . $category_group;
+            $sql .= ' AND category_group = ' . (int) $category_group;
         }
         $sql .= ' ORDER BY xc.`position` ASC ';
 
--- 4.0.0/modules/tvcmsblogclasses/tvcmscommentclass.php
+++ 4.0.0_patched/modules/tvcmsblogclasses/tvcmscommentclass.php
@@ -108,7 +108,7 @@ class TvcmsCommentClass extends ObjectMo
         if ($id_post == null) {
             return false;
         }
-        $sql = 'SELECT * FROM `' . _DB_PREFIX_ . 'tvcms_comments` xc  WHERE xc.`id_post` = ' . $id_post
+        $sql = 'SELECT * FROM `' . _DB_PREFIX_ . 'tvcms_comments` xc  WHERE xc.`id_post` = ' . (int) $id_post
              . ' AND xc.active = 1 ORDER BY xc.position DESC ';
         $rslts = Db::getInstance()->executeS($sql);
 
@@ -121,7 +121,7 @@ class TvcmsCommentClass extends ObjectMo
             return false;
         }
         $sql = 'SELECT COUNT(id_tvcms_comments) AS total_comment FROM `' . _DB_PREFIX_ . 'tvcms_comments` xc '
-             . ' WHERE xc.`id_post` = ' . $id_post;
+             . ' WHERE xc.`id_post` = ' . (int) $id_post;
         $rslts = Db::getInstance()->executeS($sql);
 
         return isset($rslts) ? $rslts['0']['total_comment'] : false;

--- 4.0.0/modules/tvcmsblogclasses/tvcmspostsclass.php
+++ 4.0.0_patched/modules/tvcmsblogclasses/tvcmspostsclass.php
@@ -375,7 +375,7 @@ class TvcmsPostsClass extends ObjectMode
             self::deleteTagPost($id_post);
             if (isset($category_ids) && !empty($category_ids)) {
                 foreach ($category_ids as $id_category) {
-                    $queryval .= '(' . (int) $id_post . ',' . (int) $id_category . ',"' . $tag . '"),';
+                    $queryval .= '(' . (int) $id_post . ',' . (int) $id_category . ',"' . pSQL($tag) . '"),';
                 }
                 $queryval = rtrim($queryval, ',');
                 if (Db::getInstance()->execute('INSERT INTO `' . _DB_PREFIX_
@@ -408,7 +408,7 @@ class TvcmsPostsClass extends ObjectMode
         }
 
         if (Db::getInstance()->execute('DELETE FROM ' . _DB_PREFIX_ . 'tvcms_category_post WHERE id_post = '
-                . $id_post . ' AND type = "' . $tag . '"')) {
+                . (int) $id_post . ' AND type = "' . pSQL($tag) . '"')) {
             return true;
         } else {
             return false;
@@ -429,7 +429,7 @@ class TvcmsPostsClass extends ObjectMode
         INNER JOIN `' . _DB_PREFIX_ . 'tvcmsposts_shop` xcs ON (xc.`id_tvcmsposts` = xcs.`id_tvcmsposts` '
              . 'AND xcs.`id_shop` = ' . $id_shop . ')
         ';
-        $sql .= ' WHERE xc.`post_type` = "' . ($post_type ? $post_type : 'post') . '" AND xc.`id_tvcmsposts` = ' . $id_post;
+        $sql .= ' WHERE xc.`post_type` = "' . ($post_type ? pSQL($post_type) : 'post') . '" AND xc.`id_tvcmsposts` = ' . (int) $id_post;
         $rslts = Db::getInstance()->getrow($sql);
 
         return $rslts;
@@ -447,8 +447,8 @@ class TvcmsPostsClass extends ObjectMode
             . $id_lang . ') INNER JOIN `' . _DB_PREFIX_ . 'tvcmsposts_shop` xcs ON '
              . '(xc.`id_tvcmsposts` = xcs.`id_tvcmsposts` '
              . 'AND xcs.`id_shop` = ' . $id_shop . ') ';
-        $sql .= ' WHERE xc.`post_type` = "' . ($post_type ? $post_type : 'post') . '" AND xcl.`link_rewrite` = "'
-            . $rewrite . '" ';
+        $sql .= ' WHERE xc.`post_type` = "' . ($post_type ? pSQL($post_type) : 'post') . '" AND xcl.`link_rewrite` = "'
+            . pSQL($rewrite) . '" ';
         $rslts = Db::getInstance()->getrow($sql);
 
         return isset($rslts['id_tvcmsposts']) ? $rslts['id_tvcmsposts'] : null;
@@ -460,7 +460,7 @@ class TvcmsPostsClass extends ObjectMode
             return false;
         }
         $sql = 'SELECT xc.`id_tvcmsposts` FROM `' . _DB_PREFIX_ . 'tvcmsposts` xc WHERE xc.`post_type` = "'
-            . ($post_type ? $post_type : 'post') . '" AND xc.active = 1 AND xc.`id_tvcmsposts` = ' . $id_post;
+            . ($post_type ? pSQL($post_type) : 'post') . '" AND xc.active = 1 AND xc.`id_tvcmsposts` = ' . (int) $id_post;
         $rslts = Db::getInstance()->getrow($sql);
 
         $tmp = $rslts['id_tvcmsposts'];
@@ -483,7 +483,7 @@ class TvcmsPostsClass extends ObjectMode
             . $id_lang . ') INNER JOIN `' . _DB_PREFIX_ . 'tvcmsposts_shop` xcs ON '
              . '(xc.`id_tvcmsposts` = xcs.`id_tvcmsposts` '
              . 'AND xcs.`id_shop` = ' . $id_shop . ') ';
-        $sql .= ' WHERE xc.`post_type` = "' . ($post_type ? $post_type : 'post') . '" AND xc.`id_tvcmsposts` = "' . $id . '" ';
+        $sql .= ' WHERE xc.`post_type` = "' . ($post_type ? pSQL($post_type) : 'post') . '" AND xc.`id_tvcmsposts` = "' . (int) $id . '" ';
         $rslts = Db::getInstance()->getrow($sql);
 
         return isset($rslts['link_rewrite']) ? $rslts['link_rewrite'] : null;
@@ -502,8 +502,8 @@ class TvcmsPostsClass extends ObjectMode
         INNER JOIN `' . _DB_PREFIX_ . 'tvcmscategory_shop` xcs ON (xc.`id_tvcmscategory` = xcs.`id_tvcmscategory` '
              . 'AND xcs.`id_shop` = ' . $id_shop . ')
         ';
-        $sql .= ' WHERE xc.`category_type` = "' . ($category_type ? $category_type : 'category') . '" AND'
-             . ' xc.`id_tvcmscategory` = ' . $id_category;
+        $sql .= ' WHERE xc.`category_type` = "' . ($category_type ? pSQL($category_type) : 'category') . '" AND'
+             . ' xc.`id_tvcmscategory` = ' . (int) $id_category;
         $rslts = Db::getInstance()->getrow($sql);
 
         return $rslts;
@@ -523,7 +523,7 @@ class TvcmsPostsClass extends ObjectMode
         INNER JOIN `' . _DB_PREFIX_ . 'tvcmscategory_shop` xcs ON (xc.`id_tvcmscategory` = xcs.`id_tvcmscategory` '
              . 'AND xcs.`id_shop` = ' . $id_shop . ')
         ';
-        $sql .= ' WHERE xc.`category_type` = "tag" AND xcl.`name` = "' . $tag . '"';
+        $sql .= ' WHERE xc.`category_type` = "tag" AND xcl.`name` = "' . pSQL($tag) . '"';
         $rslts = Db::getInstance()->getrow($sql);
         if (isset($rslts) && !empty($rslts)) {
             return $rslts['id_tvcmscategory'];
@@ -565,7 +565,7 @@ class TvcmsPostsClass extends ObjectMode
         INNER JOIN `' . _DB_PREFIX_ . 'tvcmscategory_shop` xcs ON (xcp.`id_category` = xcs.`id_tvcmscategory` '
              . 'AND xcs.`id_shop` = ' . $id_shop . ')
         ';
-        $sql .= ' WHERE xcp.`id_post` = ' . $id_post . ' AND xcp.`type` = "' . $tag . '"';
+        $sql .= ' WHERE xcp.`id_post` = ' . (int) $id_post . ' AND xcp.`type` = "' . pSQL($tag) . '"';
         $rslts = Db::getInstance()->executeS($sql);
         if (isset($rslts) && !empty($rslts)) {
             $countrslts = count($rslts);
@@ -593,13 +593,13 @@ class TvcmsPostsClass extends ObjectMode
         $id_shop = (int) Context::getContext()->shop->id;
         $sql = 'SELECT xcp.`id_category`,xcl.`name`,xcl.`link_rewrite` FROM `' . _DB_PREFIX_ . 'tvcms_category_post` xcp 
         INNER JOIN `' . _DB_PREFIX_ . 'tvcmscategory` xc ON (xcp.`id_category` = xc.`id_tvcmscategory` AND '
-             . 'xc.`category_type` = "' . $tag . '")
+             . 'xc.`category_type` = "' . pSQL($tag) . '")
         INNER JOIN `' . _DB_PREFIX_ . 'tvcmscategory_lang` xcl ON (xcp.`id_category` = xcl.`id_tvcmscategory` '
              . 'AND xcl.`id_lang` = ' . $id_lang . ')
         INNER JOIN `' . _DB_PREFIX_ . 'tvcmscategory_shop` xcs ON (xcp.`id_category` = xcs.`id_tvcmscategory` '
              . 'AND xcs.`id_shop` = ' . $id_shop . ')
         ';
-        $sql .= ' WHERE xcp.`id_post` = ' . $id_post . ' AND xcp.`type` = "' . $tag . '"';
+        $sql .= ' WHERE xcp.`id_post` = ' . (int) $id_post . ' AND xcp.`type` = "' . pSQL($tag) . '"';
         $rslts = Db::getInstance()->executeS($sql);
         if (isset($rslts) && !empty($rslts)) {
             $i = 0;
@@ -640,7 +640,7 @@ class TvcmsPostsClass extends ObjectMode
         INNER JOIN `' . _DB_PREFIX_ . 'tvcmscategory_shop` xcs ON (xc.`id_tvcmscategory` = xcs.`id_tvcmscategory` '
              . 'AND xcs.`id_shop` = ' . $id_shop . ')
         ';
-        $sql .= ' WHERE xc.`category_type` = "' . $tag . '" ';
+        $sql .= ' WHERE xc.`category_type` = "' . pSQL($tag) . '" ';
         $sql .= ' ORDER BY xc.`id_tvcmscategory` DESC ';
         $sql .= ' LIMIT ' . (int) $count;
         $rslts = Db::getInstance()->executeS($sql);
@@ -684,10 +684,10 @@ class TvcmsPostsClass extends ObjectMode
         ';
         $sql .= ' WHERE xc.`active` = 1 ';
         if ((int) $category != 0) {
-            $sql .= ' AND xc.category = ' . $category;
+            $sql .= ' AND xc.category = ' . (int) $category;
         }
         if ($post_type != null) {
-            $sql .= ' AND xc.post_type = "' . $post_type . '" ';
+            $sql .= ' AND xc.post_type = "' . pSQL($post_type) . '" ';
         }
         $sql .= ' ORDER BY xc.`position` DESC ';
         $queryexec = Db::getInstance()->getrow($sql);
@@ -720,10 +720,13 @@ class TvcmsPostsClass extends ObjectMode
         ';
         $sql .= ' WHERE xc.`active` = 1 ';
         if ((int) $category != 0) {
-            $sql .= ' AND xc.category = ' . $category;
+            $sql .= ' AND xc.category = ' . (int) $category;
         }
         if ($post_type != null) {
-            $sql .= ' AND xc.post_type = "' . $post_type . '" ';
+            $sql .= ' AND xc.post_type = "' . pSQL($post_type) . '" ';
+        }
+        if (Validate::isOrderWay($order_by) === false){
+           $order_by = 'DESC';
         }
         $sql .= ' ORDER BY xc.`position`  ' . $order_by;
         $sql .= ' LIMIT ' . (((int) $p - 1) * (int) $n) . ',' . (int) $n;
@@ -839,7 +842,10 @@ class TvcmsPostsClass extends ObjectMode
         ';
         $sql .= ' WHERE xc.`active` = 1 ';
         if ($post_type != null) {
-            $sql .= ' AND xc.post_type = "' . $post_type . '" ';
+            $sql .= ' AND xc.post_type = "' . pSQL($post_type) . '" ';
+        }
+        if (Validate::isOrderWay($order_by) === false){
+           $order_by = 'DESC';
         }
         $sql .= ' ORDER BY xc.`comment_count` ' . $order_by;
         $sql .= ' LIMIT ' . (int) $count;
@@ -940,7 +946,10 @@ class TvcmsPostsClass extends ObjectMode
         ';
         $sql .= ' WHERE xc.`active` = 1 ';
         if ($post_type != null) {
-            $sql .= ' AND xc.post_type = "' . $post_type . '" ';
+            $sql .= ' AND xc.post_type = "' . pSQL($post_type) . '" ';
+        }
+        if (Validate::isOrderWay($order_by) === false){
+           $order_by = 'DESC';
         }
         $sql .= ' ORDER BY xc.`id_tvcmsposts` ' . $order_by;
         $sql .= ' LIMIT ' . (int) $count;
@@ -1172,7 +1181,10 @@ class TvcmsPostsClass extends ObjectMode
         ';
         $sql .= ' WHERE xc.`active` = 1 ';
         if ($post_type != null) {
-            $sql .= ' AND xc.post_type = "' . $post_type . '" ';
+            $sql .= ' AND xc.post_type = "' . pSQL($post_type) . '" ';
+        }
+        if (Validate::isOrderWay($order_by) === false){
+           $order_by = 'DESC';
         }
         $sql .= ' ORDER BY xc.`position`  ' . $order_by;
         $sql .= ' LIMIT ' . (((int) $p - 1) * (int) $n) . ',' . (int) $n;
```

## Other recommendations
​
* It’s recommended to upgrade to the latest version of the module **tvcmsblog**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality WILL NOT protect your SHOP against injection SQL which uses the UNION clause to steal data.
* These HTTP headers are not supposed to be used on a final application, since they should be used only if `REMOTE_ADDR` is allowed with modules like mod_remoteip for Apache2, so you should auto-delete them if you are not behind a well setup load-balancer or reverse proxy.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942’s rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

​
​
## Timeline
​
| Date | Action |
|--|--|
| 2023-02-10 | Issue discovered during a code review by [TouchWeb.fr](https://touchweb.fr) and documented by [202-ecommerce.com](https://www.202-ecommerce.com/) |
| 2023-02-10 | Contact PrestaShop Addons security Team to confirm version scope by author |
| 2023-02-15 | The author provided a patch, but it still contains all the critical vulnerabilities. |
| 2023-03-05 | Request a CVE ID |
| 2023-03-16 | Received CVE ID |
| 2023-04-13 | Recontact PrestaShop Addons security Team to confirm version scope by author |
| 2023-10-25 | Publish this advisory and the CVE |
​


## Links
​
* [PrestaShop addons product page](https://addons.prestashop.com/fr/themes-electronique-high-tech/29992-electron-mega-electronique-high-tech-store.html)
* [Author product page](https://themevolty.com/electron-mega-electronic-store)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-27846)
