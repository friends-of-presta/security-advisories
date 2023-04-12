---
layout: post
title: "[CVE-2020-9368][CWE-22] Path traversal in Olea Gift On Order module (giftonorder) module for PrestaShop"
categories: module
author:
- Intrinsec
meta: "CVE,PrestaShop,giftonorder"
severity: "high (7.5)"
---

The Module Olea Gift On Order module through 5.0.8 for PrestaShop enables an unauthenticated user to read arbitrary files on the server via getfile.php?file=/.. directory traversal.

## Summary

* **CVE ID**: [CVE-2020-9368](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9368)
* **Published at**: 2020-11-02
* **Advisory source**: Intrinsec
* **Vendor**: PrestaShop
* **Product**: giftonorder
* **Impacted release**: <= 5.0.8
* **Product author**: Oleacorner
* **Weakness**: [CWE-22](https://www.cvedetails.com/cwe-details/22/cwe.html)
* **Severity**: high (7.5)

## Description

Olea Gift On Order module through 5.0.8 for PrestaShop enable an unauthenticated user to read arbitrary files on the server via getfile.php?file=/.. directory traversal.

As there is no access control over the getfile.php page, any unauthenticated user can call this file in their browser to retrieve the content of any page in any (sub)folder of the Prestashop folder.
This is done by making a GET request to getfile.php with file parameter set to the file the user wants to retrieve.

The _PS_ROOT_DIR (root of the Prestashop folder) variable is prepended to the file being retrieved. However, as there is no filtering on the input passed in file GET parameter, by prepending several ../ a user can retrieve files outside of the Prestashop directory.

## Solutions

* Manual removal of the getfile.php file as suggested by Oleacorner.
* No patch will be provided by the publisher.

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

* Obtain database access
* Extract sensitive data, such as tokens or private keys stored in config files
* Extract other private data, such as log files or exports

## Timeline

| Date | Action |
| -- | -- |
| 2023-02-11 | Publish the security advisory |

## Links

* [National Vulnerability Database CVE-2020-9368](https://nvd.nist.gov/vuln/detail/CVE-2020-9368)
* [Intrinsec blog post](https://github.com/Intrinsec/CERT/blob/master/Advisories/CVE-2020-9368.md)
