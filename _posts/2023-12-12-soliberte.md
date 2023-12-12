---
layout: post
title: "[CVE-2023-40921] Improper neutralization of a SQL parameter in deprecated soliberte module from Common Services for PrestaShop"
categories: modules
author:
- 202-ecommerce.com
- TouchWeb.fr
- Friends-Of-Presta.org
meta: "CVE,PrestaShop,soliberte"
severity: "critical (9.8)"
---


In the module "soliberte" for PrestaShop, an attacker can perform a SQL injection from >= 4.0.0 and < 4.3.03. Release 4.3.03 fixed this security issue.

## Summary

* **CVE ID**: [CVE-2023-40921](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-40921)
* **Published at**: 2023-12-12
* **Advisory source**: Friends-Of-Presta.org
* **Platform**: PrestaShop
* **Product**: soliberte
* **Impacted release**: >= 4.0.0 and < 4.3.03 (4.3.03 fixed issue)
* **Product author**: Common Services
* **Weakness**: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
* **Severity**: critical (9.8)

## Description

Before 4.3.03, a sensitive SQL calls in file `functions/point_list.php` can be executed with a trivial http call and exploited to forge a blind SQL injection throught the POST or GET submitted `lat` and `lng` variables.


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

* Technical and personal data leaks
* Obtain admin access
* Remove all data of the linked PrestaShop
* Display sensitives tables to front-office to unlock potential admin's ajax scripts of modules protected by token on the ecosystem


## Patch

```diff
--- a/modules/soliberte/classes/socolissimo.class.php
+++ b/modules/soliberte/classes/socolissimo.class.php
@@ -822,7 +822,7 @@ class So_Colissimo extends Module
        public function lookup_latlng($lat, $lng, $limiter = 30)
        {
                $countDeactivateCarrier = 0;
-               $formula = "(6366*acos(cos(radians('$lat'))*cos(radians(`lat`))*cos(radians(`lng`) -radians('$lng'))+sin(radians('$lat'))*sin(radians(`lat`))))";
+               $formula = "(6366*acos(cos(radians('" . (float)$lat . "'))*cos(radians(`lat`))*cos(radians(`lng`) -radians('" . (float)$lng . "'))+sin(radians('" . (float)$lat . "'))*sin(radians(`lat`)))>
                // meme principe que chmod pour savoir lesquels ne sont pas a inclure dans la recherche
                if (!Configuration::get('SOLIBERTE_BPR'))
                        $countDeactivateCarrier += 4;
@@ -899,8 +899,8 @@ class So_Colissimo extends Module
                {
                        case $this->_retrait :
                                if ($lat)
-                                       $formula = "(6366*acos(cos(radians('$lat'))*cos(radians(`lat`))*cos(radians(`lng`) -radians('$lng'))+sin(radians('$lat'))*sin(radians(`lat`))))";
-                               $sql = 'select `id`, `libelle`, `adresse1`, `adresse2`, `lieudit`, `indice`, `code_postal`, `commune`, `lat`, `lng`, `mobilite_reduite`, `type`, `poids` '.
+                                       $formula = "(6366*acos(cos(radians('" . (float)$lat . "'))*cos(radians(`lat`))*cos(radians(`lng`) -radians('" . (float)$lng . "'))+sin(radians('" . (float) $lat . >
+                               $sql = 'select `id`, `libelle`, `adresse1`, `adresse2`, `lieudit`, `indice`, `code_postal`, `commune`, `la t`, `lng`, `mobilite_reduite`, `type`, `poids` '.
                                        ($lat ? ', '.$formula.' as distance ' : '').
                                        ' from '.$this->_retrait.' where id = "'.(int)$pr_id.'"';
                                $tab = 0;
```


## Other recommandations

* Upgrade PrestaShop to the latest version to disable multiquery execution (separated by “;”) - be warned that this functionality **WILL NOT** protect your SHOP against injection SQL which uses the UNION clause to steal data.
* Change the default database prefix `ps_` by a new longer arbitrary prefix. Nevertheless, be warned that this is useless against blackhats with DBA senior skills because of a design vulnerability in DBMS
* Activate OWASP 942's rules on your WAF (Web application firewall), be warned that you will probably break your backoffice and you will need to pre-configure some bypasses against these set of rules.



## Timeline

| Date | Action |
|--|--|
| 2023-08-12 | Vunlnerability found during a audit by [202 ecommerce](https://www.202-ecommerce.com/) |
| 2023-08-16 | Contact PrestaShop addons teams to get the scope |
| 2023-09-18 | PrestaShop addons teams confirm the issue and supply a fixed release |
| 2023-08-15 | Request a CVE ID |
| 2023-08-25 | Received CVE ID |
| 2023-12-12 | Publication of this advisory |


## Links

* [Author product page](https://common-services.com/fr/modules/)
* [National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2023-40921)

