
## Guideline to submit a complete new PrestaShop module CVE  

### 0. When to publish ?
- If the vulnerability is NOT already public, please contact security/at/friendsofpresta.org
- Don't publish a Pull Request as long as you received your CVE-ID

### 1. Write an advisory file 
- Just follow the [Friends of Presta's security advisories](https://github.com/friends-of-presta/security-advisories) steps
- NB: for *Severity score* and *Vector string* you can refer to [CVSS calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)

### 2. Request a CVE-ID
   1. Go to the [CVE request form](https://cveform.mitre.org/)
   2. Select a request type: ```Report Vulnerability/Request CVE ID```
   3. Fill your email
   4. Enter a PGP Key (to encrypt): *(optional)*
   5. Number of vulnerabilities reported or IDs requested (1-10): ```1``` 
   6. Accept conditions
   7. Vulnerability type: (choose the type closest to your request)
   8. Vendor of the product(s): (author of the module)
   9. Affected product(s)/code base: 
      1. (module folder name) 
      2. (affected versions)
   10. Has vendor confirmed or acknowledged the vulnerability?: (If you contacted the vendor about the vulnerability does he responded to you ? ) 
       1. **{règles à définir en délai d'attente + nb de relances ?}**
   11. Attack type: (in most cases ```Local```. If XSS prefer ```Physical```)
   12. Impact: (XSS,SQL Injection in most cases ```Code Excecution``` and ```Escalation of Privileges	```. Other case ```Information Disclosure``` and/or ```Other```)
   13. Affected components: (list all sensitive files)
   14. Attack vector(s): (example ```curl -v 'https://preprod.XXX/modules/impactedmodule/ajax.php?token=\'.die("22")'```)
   15. Suggested description of the vulnerability for use in the CVE info: (you can fill it with text and description of your advisory file)
   16. Discoverer(s)/Credits: (keep empty)
   17. Reference(s): (Links about the module. Module page would be the best but the domain of creator's module website could be good too)
   18. Additional information: *(optional)*
   19. Submit

### 3. During waiting for CVE-ID (response might take 1 or 2 months)
- You can publish an article/post on your own website *(optional)*

### 4. Publish a pull request for your advisory file 
- on [Friends of Presta's security advisories reporitory](https://github.com/friends-of-presta/security-advisories)

### 5. Publish your CVE
   1. After you received your CVE-ID go to the [CVE request form](https://cveform.mitre.org/)
   2. Select a request type: ```Notify CVE about a publication```
   3. Fill your email
   4. Enter a PGP Key (to encrypt): *(optional)*
   5. Link to the advisory: (the fop page url about your CVE or your own website article/post)
   6. CVE IDs of vulnerabilities to be published: (list of associated CVE-ID)
   7. Additional information and CVE ID description updates: (explain why you do this update)
   8. Date published (e.g., mm/dd/yyyy): *(optional)*
   9. Submit


### THANK YOU