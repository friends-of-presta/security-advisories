---
layout: post
title: "[CWE-502] Exploring the perils of implicit deserialization of a phar in PrestaShop (part 2)"
categories: research
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,CWE-502"
severity: "critical (10)"
---

"The PHP documentation reveals that PHAR manifest files contain serialized metadata. Crucially, if you perform any filesystem operations on a `phar://` stream, this metadata is implicitly deserialized. This means that a phar:// stream can potentially be a vector for exploiting insecure deserialization, provided that you can pass this stream into a filesystem method. 

[Source](https://portswigger.net/web-security/deserialization/exploiting#phar-deserialization)

## Summary

* **Published at**: 2023-09-04
* **Platform**: All CMS espacially PrestaShop. 
* **Weakness**: [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
* **Severity**: critical (10)


## Implicit deserialization of a phar disguised as an image (part 2)


This is a variant of the same malicious deserialization triggering previouly highlighted "[Exploring the perils of unsafe unserialize() in PrestaShop (part 1)](https://security.friendsofpresta.org/research/2023/08/28/deserialization-untrusted-data-CWE-502-part1.html)" with another attack vector.

This security issue is not new. In 2018, the [CVE-2018-19126](https://github.com/farisv/PrestaShop-CVE-2018-19126) touched the PrestaShop core. Fortunately, the exploit was available only as administrator.

This CVE was the first alert send in 2018 that proves the execution of remote code through the deseralization of an untrusted files (here a phar uploaded instead of a pdf).

**WARNING** : This is the most dangerous critical chain of our ecosystem and you will nearly never seen any CVE about it.

### How it works ?

We highly recommend to read carefully this blog post about [exploiting PHP Phar deserialization vulnerabilities](https://www.keysight.com/blogs/tech/nwvs/2020/07/23/exploiting-php-phar-deserialization-vulnerabilities-part-1) to understand it.

In summary, the following PHP methods accept php wrappers http://, data://, file:// and also phar://.

But the phar (PHp ARchive) particularity is the ability to implicitly unserialize each serialized string inside in a file.

Here is a list of [filesystem functions](https://www.php.net/manual/en/ref.filesystem.php) that trigger phar deserialization:

| | | | |
| ------|-----|-----|-----|
| `copy` | `file_exists` | `file_get_contents` | `file_put_contents` |
| `file` | `fileatime` | `filectime` | `filegroup` |
| `fileinode` | `filemtime` | `fileowner` | `fileperms` |
| `filesize` | `filetype` | `fopen` | `is_dir` |
| `is_executable` | `is_file`| `is_link` | `is_readable` |
| `is_writable` | `lstat` | `mkdir` | `parse_ini_file` |
| `readfile` | `touch` | `unlink` | `stat` | 
| `getimagesize` | `imagecreatefrom(jpeg|gif|png)` | | |

This other article shows how to [disguise a phar as a jpeg file](https://www.nc-lp.com/blog/disguise-phar-packages-as-images).

So, an attacker can craft a perfect image with mime type, extensions, ... validations and exploit the implicit unserialization by adding a malicious payload.

### Proof of concept

**FOR EDUCATIONAL PURPOSES ONLY. DO NOT USE THIS SCRIPT FOR ILLEGAL ACTIVITIES. THE AUTHOR IS NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE.**

1. Create a module and put this sample file in the module dir.

```php
// modules/mymodule/mymodule.php

class Mymodule
{
...
    public function getContent()
    {
        $isExists = file_exists('phar://phar.jpg');

        return $isExists;
    }
...
```
Note: For security reasons, the phar.jpg file is not supplied in this POC.

2. Go to the configuration page of the module.

3. This piece of code will put an `a.php` file in the designated directory of PrestaShop.


### What should be remembered?

As you can see, to be exploited, you'll have a chain of vulnerabilities composed by:

1. Firstly, the hacker should upload a static file like an image, a PDF, ... that contains a malicious payload.

PrestaShop core `ImageManager::validateUpload` class cannot filter this kind of fake "phar" especially images. The upload of a phar as an image on the product page removed the payload (by resizing it), but not in the CMS page WYSIWYG.

We could classify this vulnerability as [CWE-646](https://cwe.mitre.org/data/definitions/646.html), but this weakness can only be exploited with a second weakness.

2. Secondly, the hacker should exploit an untrusted filesystem method like `getimagesize($_GET['param'])` (or `$_POST`, `$_COOKIE`, ...). But this kind of path traversal `getimagesize( _PS_ROOT_DIR_ . $_GET['param'])` cannot be exploited for a malicious deserialization. 

On the other hand, PrestaShop core methods `ImageManager::thumbnail($_GET['param'], ...)`, `ImageManager::getMimeType($_GET['param'])`, ... call `file_exists` or `getimagesize` witch trigger phar deserialization.

Path traversal [CWE-22](https://cwe.mitre.org/data/definitions/22.html) and SSRF [CWE-918](https://cwe.mitre.org/data/definitions/918.html) could be exploited to trigger a phar deserialization.


**BECAREFUL**: The probability to register in a single third part (module, dependency) of PrestaShop both vulnerabilities is quite low. Moreover, each weakness in CWE-646 and CWE-918 (or CWE-22) in several modules in the third part is unusable separately but a combination of both is critical. **That's why the majority of exploits will fly under the radar.**

### How to prevent this vulnerability?

Phar wrapper cannot be disabled via a php.ini settings.

As a developer:
* A strict validation of input data is absolutely essential!
* Use `basename()` PHP method to prevent path traversal `getimagesize(_PS_IMG_DIR_ . basename($_GET['param']))` and unwanted use of wrapper such as `phar://`
* Use the GD library to remove dummy serialized data from an image.

As an admin sys:
* Set your firewall with [OWASP rules to filter "phar://"](https://github.com/coreruleset/coreruleset/blob/e36f27e1429a841e91996f4a521d40c996ec74eb/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf#L213)

