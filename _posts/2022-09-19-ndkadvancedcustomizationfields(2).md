---
layout: post
title: "[CVE-2022-40840] ndk design NdkAdvancedCustomizationFields 3.5.0 is vulnerable to Cross Site Scripting (XSS) via createPdf.php"
categories: module
author:
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ndkadvancedcustomizationfields"
severity: "medium (6.1)"
---

ndk design NdkAdvancedCustomizationFields 3.5.0 is vulnerable to Cross Site Scripting (XSS) via createPdf.php

## Summary

* **CVE ID**: [CVE-2022-40840](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40840)
* **Published at**: 2022-11-01
* **Advisory source**: [github](https://github.com/daaaalllii/cve-s/blob/main/CVE-2022-40840/poc.txt)
* **Vendor**: PrestaShop
* **Product**: NdkAdvancedCustomizationFields
* **Impacted release**: <= 3.5.0
* **Product author**: 
* **Weakness**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
* **Severity**: medium (6.1)

## Description

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: required
* **Scope**: changed
* **Confidentiality**: low
* **Integrity**: low
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

## Possible malicious usage

## Patch

Added a tag-removing line after the setting of $content :

```
	$content = NdkCf::remove_script_tags($content);
```

Here is the function's content :

```
    public static function  remove_script_tags($html, $load = false){
        $dom = new DOMDocument();
        $dom->loadHTML($html);
        $script = $dom->getElementsByTagName('script');
    
        $remove = [];
        foreach($script as $item){
            $remove[] = $item;
        }
        //dump($remove);
    
        foreach ($remove as $item){
            $item->parentNode->removeChild($item);
        }
    
        $html = $dom->saveHTML();
        if($load){
            $html = preg_replace('/<!DOCTYPE.*?<html>.*?<body><p>/ims', '', $html);
            $html = str_replace('</p></body></html>', '', $html);
        }
        
        return $html;
    }
```


## Other recommendations

* Upgrade the module to the most recent version
* Upgrade PrestaShop to the latest version to disable multiquery executions (separated by “;”)
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.

## Timeline

| Date | Action |
| -- | -- |
| 01-11-2022 | GitHub Poc |

## Links

* [Source of this CVE](https://github.com/daaaalllii/cve-s/blob/main/CVE-2022-40840/poc.txt)
* [National Vulnerability Database CVE-2022-40840](https://nvd.nist.gov/vuln/detail/CVE-2022-40840)