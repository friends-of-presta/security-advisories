---
layout: post
title: "[CVE-2021-36748] Improper neutralization of SQL parameter in SimpleBlog module from Prestahome for PrestaShop"
categories: module
author:
- Sorcery Ltd
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ph_simpleblog"
severity: "critical (9.8)"
---

A SQL Injection issue in the list controller of the Prestahome Blog (aka ph_simpleblog) module before 1.7.8 for Prestashop allows a remote attacker to extract data from the database via the sb_category parameter.

## Summary

* **CVE ID**: [CVE-2021-36748](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36748)
* **Published at**: 2021-08-20
* **Advisory source**: [sorcery.ie](https://blog.sorcery.ie/posts/simpleblog_sqli/)
* **Platform**: PrestaShop
* **Product**: ph_simpleblog
* **Impacted release**: < 1.7.8
* **Product author**: Prestahome
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

This blog post details an SQLi sorcery.ie found in Blog for Prestashop (ph_simpleblog) by Prestahome.

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
* Copy/paste data from sensitive tables to the FRONT to exposed tokens and unlock admins's ajax scripts
* Rewrite SMTP settings to hijack emails

## Patch for version 1.7.7
```diff
diff --git a/classes/BlogPostsFinder.php b/classes/BlogPostsFinder.php
index b753146..e58fe63 100644
--- a/classes/BlogPostsFinder.php
+++ b/classes/BlogPostsFinder.php
@@ -134 +134 @@ class BlogPostsFinder
-        $this->customer = $customer;
+        $this->customer = $id_customer;
@@ -271 +271 @@ class BlogPostsFinder
-        $sql->innerJoin('simpleblog_post_lang', 'l', 'sbp.id_simpleblog_post = l.id_simpleblog_post AND l.id_lang = ' . $this->getIdLang());
+        $sql->innerJoin('simpleblog_post_lang', 'l', 'sbp.id_simpleblog_post = l.id_simpleblog_post AND l.id_lang = ' . (int) $this->getIdLang());
@@ -273 +273 @@ class BlogPostsFinder
-        $sql->innerJoin('simpleblog_post_shop', 'sbps', 'sbp.id_simpleblog_post = sbps.id_simpleblog_post AND sbps.id_shop = ' . $this->getIdShop());
+        $sql->innerJoin('simpleblog_post_shop', 'sbps', 'sbp.id_simpleblog_post = sbps.id_simpleblog_post AND sbps.id_shop = ' . (int) $this->getIdShop());
@@ -284 +284 @@ class BlogPostsFinder
-                    $child_categories[] = $child['id_simpleblog_category'];
+                    $child_categories[] = pSQL($child['id_simpleblog_category']);
@@ -323 +323 @@ class BlogPostsFinder
-                    $sql->where($this->getCustomWhere());
+                    $sql->where($condition);
diff --git a/models/SimpleBlogCategory.php b/models/SimpleBlogCategory.php
index 23badad..56d9c25 100644
--- a/models/SimpleBlogCategory.php
+++ b/models/SimpleBlogCategory.php
@@ -421 +421 @@ class SimpleBlogCategory extends ObjectModel
-            $sql->where('l.link_rewrite = \'' . $rewrite . '\' AND l.id_lang = ' . (int) $id_lang);
+            $sql->where('l.link_rewrite = \'' . pSQL($rewrite) . '\' AND l.id_lang = ' . (int) $id_lang);
@@ -423 +423 @@ class SimpleBlogCategory extends ObjectModel
-            $sql->where('l.link_rewrite = \'' . $rewrite . '\'');
+            $sql->where('l.link_rewrite = \'' . pSQL($rewrite) . '\'');
@@ -436 +436 @@ class SimpleBlogCategory extends ObjectModel
-        $sql->where('l.id_simpleblog_category = ' . $id_simpleblog_category . ' AND l.id_lang = ' . (int) $id_lang);
+        $sql->where('l.id_simpleblog_category = ' . (int) $id_simpleblog_category . ' AND l.id_lang = ' . (int) $id_lang);
@@ -461 +461 @@ class SimpleBlogCategory extends ObjectModel
-        $tmp_location = _PS_TMP_IMG_DIR_ . 'ph_simpleblog_cat_' . $object->id . '.' . $object->cover;
+        $tmp_location = _PS_TMP_IMG_DIR_ . 'ph_simpleblog_cat_' . (int) $object->id . '.' . $object->cover;
@@ -466 +466 @@ class SimpleBlogCategory extends ObjectModel
-        $orig_location = _PS_MODULE_DIR_ . 'ph_simpleblog/covers_cat/' . $object->id . '.' . $object->cover;
+        $orig_location = _PS_MODULE_DIR_ . 'ph_simpleblog/covers_cat/' . (int) $object->id . '.' . $object->cover;
diff --git a/models/SimpleBlogPost.php b/models/SimpleBlogPost.php
index 0d140a3..77ee13e 100644
--- a/models/SimpleBlogPost.php
+++ b/models/SimpleBlogPost.php
@@ -291 +291 @@ class SimpleBlogPost extends ObjectModel
-            $sql->where('sbp.id_simpleblog_post ' . $filter . ' (' . implode(',', $selected) . ')');
+            $sql->where('sbp.id_simpleblog_post ' . pSQL($filter) . ' (' . implode(',', $selected) . ')');
@@ -413 +413 @@ class SimpleBlogPost extends ObjectModel
-            $sql->where('sbp.id_simpleblog_post ' . $filter . ' (' . implode(',', $selected) . ')');
+            $sql->where('sbp.id_simpleblog_post ' . pSQL($filter) . ' (' . implode(',', $selected) . ')');
@@ -428 +428 @@ class SimpleBlogPost extends ObjectModel
-        $sql->limit($limit, $start);
+        $sql->limit((int) $limit, $start);
@@ -504 +504 @@ class SimpleBlogPost extends ObjectModel
-            $sql->where('l.link_rewrite = \'' . $rewrite . '\'');
+            $sql->where('l.link_rewrite = \'' . pSQL($rewrite) . '\'');
@@ -507 +507 @@ class SimpleBlogPost extends ObjectModel
-            $sql->where('l.link_rewrite = \'' . $rewrite . '\'');
+            $sql->where('l.link_rewrite = \'' . pSQL($rewrite) . '\'');
@@ -521 +521 @@ class SimpleBlogPost extends ObjectModel
-            $sql->where('l.link_rewrite = \'' . $rewrite . '\'');
+            $sql->where('l.link_rewrite = \'' . pSQL($rewrite) . '\'');
@@ -538 +538 @@ class SimpleBlogPost extends ObjectModel
-                    $sql->where('l.link_rewrite = \'' . $rewrite . '\' AND l.id_lang = ' . (int) $id_lang);
+                    $sql->where('l.link_rewrite = \'' . pSQL($rewrite) . '\' AND l.id_lang = ' . (int) $id_lang);
@@ -540 +540 @@ class SimpleBlogPost extends ObjectModel
-                    $sql->where('l.link_rewrite = \'' . $rewrite . '\'');
+                    $sql->where('l.link_rewrite = \'' . pSQL($rewrite) . '\'');
@@ -820 +820 @@ class SimpleBlogPost extends ObjectModel
-            $sql = 'UPDATE `' . _DB_PREFIX_ . 'simpleblog_post` SET `likes` = `likes` + 1 WHERE id_simpleblog_post = ' . $id_simpleblog_post;
+            $sql = 'UPDATE `' . _DB_PREFIX_ . 'simpleblog_post` SET `likes` = `likes` + 1 WHERE id_simpleblog_post = ' . (int) $id_simpleblog_post;
@@ -822 +822 @@ class SimpleBlogPost extends ObjectModel
-            $sql = 'UPDATE `' . _DB_PREFIX_ . 'simpleblog_post` SET `likes` = `likes` - 1 WHERE id_simpleblog_post = ' . $id_simpleblog_post;
+            $sql = 'UPDATE `' . _DB_PREFIX_ . 'simpleblog_post` SET `likes` = `likes` - 1 WHERE id_simpleblog_post = ' . (int) $id_simpleblog_post;
@@ -829 +829 @@ class SimpleBlogPost extends ObjectModel
-        $sql = 'SELECT `likes` FROM `' . _DB_PREFIX_ . 'simpleblog_post` WHERE id_simpleblog_post = ' . $id_simpleblog_post;
+        $sql = 'SELECT `likes` FROM `' . _DB_PREFIX_ . 'simpleblog_post` WHERE id_simpleblog_post = ' . (int) $id_simpleblog_post;
@@ -838 +838 @@ class SimpleBlogPost extends ObjectModel
-        $sql = 'UPDATE `' . _DB_PREFIX_ . 'simpleblog_post` SET `views` = `views` + 1 WHERE id_simpleblog_post = ' . $this->id_simpleblog_post;
+        $sql = 'UPDATE `' . _DB_PREFIX_ . 'simpleblog_post` SET `views` = `views` + 1 WHERE id_simpleblog_post = ' . (int) $this->id_simpleblog_post;
diff --git a/models/SimpleBlogPostType.php b/models/SimpleBlogPostType.php
index a4ce8e8..449efd6 100644
--- a/models/SimpleBlogPostType.php
+++ b/models/SimpleBlogPostType.php
@@ -68 +68 @@ class SimpleBlogPostType extends ObjectModel
-        $sql->where('slug = \'' . $slug . '\'');
+        $sql->where('slug = \'' . pSQL($slug) . '\''
```

## Other recommendations

* Upgrade the module to the most recent version
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 18-06-2021 | Issue discovered during a pentest |
| 13-07-2021 | Reported issue to Prestahome |
| 14-07-2021 | Prestahome patched the issue in version 1.7.8 |
| 15-07-2021 | Number CVE-2021-36748 assigned |
| 18-08-2021 | Blog post released |
| 20-08-2021 | pajoda released a Nuclei template for this CVE |

## Links

* [Source of this CVE](https://blog.sorcery.ie/posts/ph_simpleblog_sqli/)
* [National Vulnerability Database CVE-2021-36748](https://nvd.nist.gov/vuln/detail/CVE-2021-36748)
