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
* **Advisory source**: PrestaShop
* **Platform**: PrestaShop
* **Product**: Ap Page Builder
* **Impacted release**: < 4.0.0
* **Product author**: Apollo Theme
* **Weakness**: [CWE-36](https://cwe.mitre.org/data/definitions/36.html)
* **Severity**: high (8.7)

## Description

Absolute Path Traversal vulnerability in AP Page Builder versions prior to 4.0.0 could allow an unauthenticated remote user to modify the 'product_item_path' within the 'config' JSON file, allowing them to read any file on the system.

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

## Links

* [Incibe cert advisory](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/path-traversal-en-ap-page-builder)
* [Prestashop advisory](https://help-center.prestashop.com/hc/fr/articles/25492821315346-Mise-en-conformit%C3%A9-du-module-Ap-Page-Builder)
* [Theme page](https://apollotheme.com/products/ap-pagebuilder-prestashop-module)
