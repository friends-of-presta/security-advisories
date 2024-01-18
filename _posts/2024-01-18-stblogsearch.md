---
layout: post
title: "[CVE-2023-43985] Improper neutralization of SQL parameter in SunnyToo - Blog Search module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Creabilis
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,stblogsearch"
severity: "critical (9.8)"
---

In the module "Blog Search" (stblogsearch) up to version 1.0 from SunnyToo for PrestaShop, a guest can perform SQL injection in affected versions.


## Summary

* **CVE ID**: [CVE-2023-43985](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43985)
* **Published at**: 2024-01-18
* **Platform**: PrestaShop
* **Product**: stblogsearch
* **Impacted release**: <= 1.0 [See note below]
* **Product author**: SunnyToo
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Method `StBlogSearchClass::prepareSearch` has sensitive SQL calls that can be executed with a trivial http call and exploited to forge a SQL injection.

This exploit uses a PrestaShop front controller and most attackers can conceal the module controller's path during the exploit, so you will never know within your conventional frontend logs that it exploits this vulnerability. **You will only see "POST /" inside your conventional frontend logs.** Activating the AuditEngine of mod_security (or similar) is the only way to get data to confirm this exploit.

Note : the author do not have a compliant semver versionning on these modules, only on its themes which loads tens of modules. According to him, it's fixed on Panda Theme  2.8 and Transform Theme  4.7.0. So, according to its advices, you must update the whole theme.

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

## Patch from 1.0

```diff
--- 1.0/modules/stblogsearch/classes/StBlogSearchClass.php
+++ XXX/modules/stblogsearch/classes/StBlogSearchClass.php
...
        foreach ($words as $key => $search)
        {
            if (empty($search) || strlen($search) < (int)Configuration::get('ST_BS_SEARCH_MINWORDLEN'))
                continue;
            $search_extra = '';
            if (Configuration::get('ST_BS_SEARCH_NAME'))
-               $search_extra .= ' OR bl.name LIKE "%'.$search.'%"';
+               $search_extra .= ' OR bl.name LIKE "%'.pSQL($search).'%"';
            if (Configuration::get('ST_BS_SEARCH_AUTHOR
-               $search_extra .= ' OR bl.author LIKE "%'.$search.'%"';
+               $search_extra .= ' OR bl.author LIKE "%'.pSQL($search).'%"';
            if (Configuration::get('ST_BS_SEARCH_CATEGORY'))
-               $search_extra .= ' OR bcl.name LIKE "%'.$search.'%"';
+               $search_extra .= ' OR bcl.name LIKE "%'.pSQL($search).'%"';
            if (Configuration::get('ST_BS_SEARCH_SHORT_CONTENT'))
-               $search_extra .= ' OR bl.content_short LIKE "%'.$search.'%"';
+               $search_extra .= ' OR bl.content_short LIKE "%'.pSQL($search).'%"';
            if (Configuration::get('ST_BS_SEARCH_CONTENT'))
-               $search_extra .= ' OR bl.content LIKE "%'.$search.'%"';
+               $search_extra .= ' OR bl.content LIKE "%'.pSQL($search).'%"';
            
            if (!$search_extra)
                return false;
            
            // Search in blog lang and category lang.
            $result = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS('
            SELECT bl.id_st_blog FROM `'._DB_PREFIX_.'st_blog_lang` bl 
            INNER JOIN `'._DB_PREFIX_.'st_blog_shop` bs ON (bs.id_st_blog=bl.id_st_blog)
            LEFT JOIN `'._DB_PREFIX_.'st_blog_category_blog` bcb ON (bl.id_st_blog=bcb.id_st_blog)
            LEFT JOIN `'._DB_PREFIX_.'st_blog_category_lang` bcl ON (bcb.id_st_blog_category=bcl.id_st_blog_category
            AND bcl.`id_lang` = '.$id_lang.')
            WHERE bl.`id_lang` ='.$id_lang.'
            AND bs.`id_shop` = '.$id_shop.'
            AND ('.trim($search_extra, ' OR ').')
            ');
        
            if($result)
        		foreach ($result as $row)
                    $id_array[] = $row['id_st_blog'];
            
            if (Configuration::get('ST_BS_SEARCH_TAG'))
            {
                // Search in blog tag.
                $result = Db::getInstance(_PS_USE_SQL_SLAVE_)->executeS('
                SELECT id_st_blog FROM `'._DB_PREFIX_.'st_blog_tag` t 
                INNER JOIN `'._DB_PREFIX_.'st_blog_tag_map` tm 
                ON (t.id_st_blog_tag=tm.id_st_blog_tag)
                WHERE id_lang = '.$id_lang.'
-               AND name like "%'.$search.'%"
+               AND name like "%'.pSQL($search).'%"
                ');
                if($result)
            		foreach ($result as $row)
                        $id_array[] = $row['id_st_blog'];    
            }
      }
```


## Other recommendations

* It’s recommended to upgrade to the latest version of the module **stblogsearch**.
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` with a new longer, arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-08-29 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-08-29 | Contact Author to confirm versions scope |
| 2023-08-29 | Author confirm versions scope |
| 2023-09-21 | Request a CVE ID |
| 2023-09-27 | Received CVE ID |
| 2024-01-18 | Publish this security advisory |

## Links

* [Author product page](https://www.sunnytoo.com/product/panda-creative-responsive-prestashop-theme)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-43985)
