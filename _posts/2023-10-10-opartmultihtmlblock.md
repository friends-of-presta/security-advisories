---
layout: post
title: "[CVE-2023-30148] Multiple cross-site scripting (XSS) vulnerabilities in the Multi html block (opartmultihtmlblock) module and multihtmlblock* sub-modules from Opart for PrestaShop"
categories: modules
author:
- Profileo.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,opartmultihtmlblock,multihtmlblock"
severity: "medium (6.1)"
---

Multiple cross-site scripting (XSS) vulnerabilities of Type 2 (Stored XSS) B2F (Back to front) in the Multi html block (opartmultihtmlblock) module and multihtmlblock* sub-modules from Opart for PrestaShop, prior to version 2.0.12, allows remote authenticated users to inject arbitrary web script or HTML via the `body_text` or `body_text_rude` field.

## Summary

* **CVE ID**: [CVE-2023-30148](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30148)
* **Published at**: 2023-10-10
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: opartmultihtmlblock and multihtmlblock* sub-modules
* **Impacted release**: For opartmultihtmlblock <= 2.0.11 (Fixed in 2.0.12), for multihtmlblock* : = 1.0.0
* **Product author**: Opart
* **Weakness**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
* **Severity**: medium (6.1)

## Description

Prior to version 2.0.12 of the Prestashop Multi html block (opartmultihtmlblock) module and multihtmlblock* sub-modules for PrestaShop, scripts can be injected into the database by the admin configuration form or chained by an SQL injection, which can then be executed in user browsers.

**WARNING**: This vulnerability has been seen as exploited to inject malicious code into the payment page using the `displayBanner` hook from the `multihtmlblockmessageheader` sub-module (exploited by a compromised admin).

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: high
* **User interaction**: required
* **Scope**: unchanged
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: none

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:N)

## Possible malicious usage

* Hijack payment modules
* Redirect users to another website
* Technical and personal data leaks

## Patch 

Patches listed below will:
1. Sanitize the admin form (removing scripts thanks to `isCleanHtml` validate, and removing iframes is not authorized in HTML fields
2. Sanitize the string saved in the database before displaying it (to disable corrupted data from SQL injections) 

Please note that these patches should be applied to the main module opartmultihtmlblock and all multihtmlblock* sub-modules. For the main module, the component to modify is the class `BlockhtmlClass` in `sourcefiles` directory and well as the main class `Blockhtml`, and for the sub-modules, the component to edit is the `Multihtmlblock*Class` as well as the main class `Multihtmlblock*`

```diff
--- a/sourcefiles/BlockhtmlClass.php
+++ b/sourcefiles/BlockhtmlClass.php
@@ -62,8 +62,8 @@ class %Modulename%Class extends ObjectModel
                'fields' => array(
                        'id_shop' =>                            array('type' => self::TYPE_INT, 'validate' => 'isunsignedInt', 'required' => true),
                        // Lang fields
-                       'body_text' =>                  array('type' => self::TYPE_HTML, 'lang' => true, 'validate' => 'isString'),
-                        'body_text_rude' =>            array('type' => self::TYPE_HTML, 'lang' => true, 'validate' => 'isString'),
+                       'body_text' =>                  array('type' => self::TYPE_HTML, 'lang' => true, 'validate' => 'isCleanHtml'),
+                        'body_text_rude' =>            array('type' => self::TYPE_HTML, 'lang' => true, 'validate' => 'isCleanHtml'),
                         'all_pages' => array('type' => self::TYPE_BOOL, 'validate' => 'isBool'),
                         'show_on_home' =>            array('type' => self::TYPE_STRING, 'validate' => 'isBool'),
                         'category_id' =>            array('type' => self::TYPE_STRING, 'validate' => 'isString'),
```
```diff
--- a/sourcefiles/blockhtml.php
+++ b/sourcefiles/blockhtml.php
@@ -384,9 +384,27 @@ class %Modulename% extends Module
                             $blockhtml=new %Modulename%Class();
                             $blockhtml->id_shop=$id_shop;                                
                             $blockhtml->copyFromPost();
+                            // Validate if our html fields contains an iframe
+                            $isIframeValidated = $this->validateIframe($blockhtml->body_text);
+                            $isIframeValidated = $isIframeValidated ?
+                                $this->validateIframe($blockhtml->body_text_rude) :
+                                $isIframeValidated;
+                            if (!$isIframeValidated) {
+                                // There is an iframe that is not allowed, we stop here
+                                return false;
+                            }
                             $blockhtml->save();
                        }
                         $blockhtml->copyFromPost();
+                        // Validate if our html fields contains an iframe
+                        $isIframeValidated = $this->validateIframe($blockhtml->body_text);
+                        $isIframeValidated = $isIframeValidated ?
+                            $this->validateIframe($blockhtml->body_text_rude) :
+                            $isIframeValidated;
+                        if (!$isIframeValidated) {
+                            // There is an iframe that is not allowed, we stop here
+                            return false;
+                        }
                         $blockhtml->update();
                         
                        $this->messages[]=$this->l('Block successfuly update');
@@ -395,6 +413,25 @@ class %Modulename% extends Module
                }
        }
 
+    /**
+     * Validate a string depending if iframes are allowed in HTML fields
+     *
+     * @param string $htmlBody
+     *
+     * @return bool
+     */
+    protected function validateIframe($htmlBody)
+    {
+        foreach ($htmlBody as $stringToValidate) {
+            if (!Configuration::get('PS_ALLOW_HTML_IFRAME') &&
+                preg_match('/<iframe.*src=\"(.*)\".*><\/iframe>/isU', $stringToValidate)) {
+                $this->erreurs[] = $this->trans('To use <iframe>, enable the feature in Shop Parameters > General');
+                return false;
+            }
+        }
+        return true;
+    }
+
         private function getIsInArray($controller_name,$obj_value,$the_get) {
             if(get_class($this->context->controller)==$controller_name && $obj_value != "") {
                 $id_array = explode(',',$obj_value);
@@ -478,7 +515,10 @@ class %Modulename% extends Module
                 
                 if(!$this->displayAllowed($blockhtml))
                     return false;
-                
+        // Remove all scripts tags (including inline scripts)
+        $blockhtml->body_text_rude = $this->sanatizeHtmlForDisplay($blockhtml->body_text_rude);
+        $blockhtml->body_text = $this->sanatizeHtmlForDisplay($blockhtml->body_text);
+
                $this->smarty->assign(array(
                        'blockhtml' => $blockhtml,
                        'default_lang' => (int)$this->context->language->id,
@@ -495,6 +535,68 @@ class %Modulename% extends Module
                     return $this->display(__FILE__, 'views/templates/ps17/blockhtml.tpl');
        }
        
+    /**
+     * Remove JavaScript from HTML
+     * Credit to : https://www.mradeveloper.com/blog/remove-javascript-from-html-with-php
+     *
+     * @param string $inputP
+     *
+     * @return string sanatized HTML
+     */
+    protected function sanatizeHtmlForDisplay($inputP)
+    {
+        $spaceDelimiter = "#BLANKSPACE#";
+        $newLineDelimiter = "#NEWLNE#";
+                                    
+        $inputArray = [];
+        $minifiedSanitized = '';
+        $unMinifiedSanitized = '';
+        $sanitizedInput = [];
+        $returnData = [];
+        $returnType = "string";
+
+        if($inputP === null) return null;
+        if($inputP === false) return false;
+        if(is_array($inputP) && sizeof($inputP) <= 0) return [];
+
+        if (is_array($inputP)) {
+            $inputArray = $inputP;
+            $returnType = "array";
+        } else {
+            $inputArray[] = $inputP;
+            $returnType = "string";
+        }
+
+        foreach($inputArray as $input)
+        {
+            $minified = str_replace(" ",$spaceDelimiter,$input);
+            $minified = str_replace("\n",$newLineDelimiter,$minified);
+
+            //removing <script> tags
+            $minifiedSanitized = preg_replace("/[<][^<]*script.*[>].*[<].*[\/].*script*[>]/i","",$minified);
+
+            $unMinifiedSanitized = str_replace($spaceDelimiter," ",$minifiedSanitized);
+            $unMinifiedSanitized = str_replace($newLineDelimiter,"\n",$unMinifiedSanitized);
+
+            //removing inline js events
+            $unMinifiedSanitized = preg_replace("/([ ]on[a-zA-Z0-9_-]{1,}=\".*\")|([ ]on[a-zA-Z0-9_-]{1,}='.*')|([ ]on[a-zA-Z0-9_-]{1,}=.*[.].*)/","",$unMinifiedSanitized);
+
+            //removing inline js
+            $unMinifiedSanitized = preg_replace("/([ ]href.*=\".*javascript:.*\")|([ ]href.*='.*javascript:.*')|([ ]href.*=.*javascript:.*)/i","",$unMinifiedSanitized);
+
+                                        
+            $sanitizedInput[] = $unMinifiedSanitized;
+        }
+
+        if ($returnType == "string" && sizeof($sanitizedInput) > 0) {
+            $returnData = $sanitizedInput[0];
+        } else {
+            $returnData = $sanitizedInput;
+        }
+                                    
+        return $returnData;
+    }
+    
        public function hookDisplayTop($param)  {
                return $this->hookDisplayLeftColumn($param);
        }
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module
* To mitigate potential issues arising from credential leaks, enforce mandatory 2FA for backoffice logins. This will necessitate the integration of a 2FA module.

## Timeline

| Date | Action |
| -- | -- |
| 2023-02-10 | First exploit detected in server logs |
| 2023-03-11 | Discovery and POC of the vulnerability by Profileo |
| 2023-03-12 | Contacting the editor |
| 2023-03-14 | Editor confirmed the vulnerability and is planning a new release of the module |
| 2023-03-15 | First patch (2.0.11) of the module suggested. Additional fixes were required |
| 2023-03-15 | New release of the module (2.0.12) |
| 2023-04-03 | The editor communicated with known customers concerning the vulnerability |
| 2023-04-21 | CVE ID Received |
| 2023-10-10 | Publishing this security advisory |

## Links

* [Editor Website store-opart](https://www.store-opart.fr/p/13-op-art-multi-html-block.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-30148)
