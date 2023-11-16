---
layout: post
title: "Prestashop unremoved install directory risks"
categories: core
tags: brute-force
author:
- 772424.com
- Friends-Of-Presta.org
---

Prestashop installation directory should be deleted after a successful installation.
It should not be renamed, as the remaining directory can contain code that is exploitable if publicly accessible, such as:
 - tool to sync information in database
 - tool to extract db information in xml files

![Install dir tool]({{ "/assets/img/install_dir_tool.png" | relative_url }})

## Why is my renamed install directory link is known ?

We have seen scan from bots that try to access several CMS known sensible directories.
The following list is not exhaustive but give an example of directories scanned

```
__install
_install
instalold
install.bck
install.back
install123
install.old
install0
install.inc
install_todelete
```

## What should I do

Check your Prestashop installation and delete the install directory.
Enable a check on your monitoring platform to detect such directory
or ask your hosting company to detect and notify you if an install directory is detected.

If you have an install directory at the root of your Prestashop installation,
you should grep your access log to check if the directory was accessed.

