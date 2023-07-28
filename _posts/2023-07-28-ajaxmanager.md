---
layout: post
title: "[CVE-2023-33493] Unrestricted Upload of File with Dangerous Type in the Ajaxmanager File and Database explorer (ajaxmanager) module from RSI for PrestaShop"
categories: module
author:
- Profileo.com
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,ajaxmanager"
severity: "critical (9.8)"
---

An "Unrestricted Upload of File with Dangerous Type" vulnerability exists in the Ajaxmanager File and Database explorer (ajaxmanager) module, from RSI, for PrestaShop, for all versions (including latest version 2.3.0). This allows remote attackers to upload dangerous files without restrictions.

## Summary

* **CVE ID**: [CVE-2023-33493](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33493)
* **Published at**: 2023-07-28
* **Advisory source**: Friends-Of-Presta
* **Platform**: PrestaShop
* **Product**: ajaxmanager
* **Impacted release**: All versions (No fix provided. Still vulnerable in the latest version 2.3.0)
* **Product author**: RSI
* **Weakness**: [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
* **Severity**: critical (9.8)

## Description

In the Ajaxmanager File and Database explorer (ajaxmanager) module for PrestaShop, remote attackers can access a file explorer without being logged in, enabling upload view and deletion of files. The file explorer tool is also providing access to a shell console, port scan and server information. Disabling or uninstalling the module is not removing the access to the tool. The issue is not fixed in the latest version.

It should be noted that the module provides users the ability to set a password to restrict access to the tool. However, the password is giving no protection. A bug allows users to access the file explorer without having to provide the password.

This vulnerability has been successfully reproduced in the versions 2.1.0, 2.2.0 and 2.3.0 (the last version to date). We believe that the issue is also existing in previous versions.

**WARNING**: Disabling or uninstalling the module will not stop the vulnerability from being exploited.

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

* Removing and altering files (without malware injection)
* Removing and altering data in the database (without malware injection)
* Optaining database password and cookie key (without malware injection)
* Uploading malwares to the website
* Obtaining complete admin access to the site

## Patch

This module contains multiple functional and technical vulnerabilities. No patch can be applied without redeveloping most of the module to introduce an authentication system.

Also, even with proper authentication system, due to the nature of the module, its usage alone can qualify it as a backdoor. As this module is not essential for PrestaShop, it's recommended to uninstall the module (and to remove the module's files).

Make sure that the following directory is removed after uninstalling the module : `/modules/ajaxmanager/`

## Timeline

| Date | Action |
| -- | -- |
| 2023-03-29 | Discovery of the vulnerability by Profileo |
| 2023-03-29 | Security issue reported to the author, in addons support platform |
| 2023-03-31 | The author did not confirm the issue |
| 2023-04-02 | Release additional details to the author to reproduce the issue |
| 2023-04-02 | The author confirmed the issue |
| 2023-04-11 | Request for a patch and offer a security audit to the author |
| 2023-04-11 | Author didn't submit a patch and wasn't able to confirm impacted versions |
| 2023-04-12 | Contact again the Author, requesting a patch |
| 2023-04-19 | Author didn't submit a patch and wasn't able to confirm impacted versions |
| 2023-05-06 | Contact again the Author with more details, requesting a patch |
| 2023-05-09 | Author didn't submit a patch and wasn't able to confirm impacted versions |
| 2023-06-07 | Received a CVE ID From MITRE |
| 2023-06-15 | Module removed from Addons platform (without patch available) |
| 2023-07-28 | Publication of the CVE |

## Links

* [Ajaxmanager File and Database explorer (ajaxmanager) Module - (Module currently disabled)](https://addons.prestashop.com/en/administrative-tools/5815-ajax-file-database-manager.html#specifications)
* [National Vulnerability Database CVE-2023-33493](https://nvd.nist.gov/vuln/detail/CVE-2023-33493)
