# Scrapy-CVE_Detail

Crawl different cve information from **https://www.cvedetails.com/**. Check the final data in data.csv


**1. Prerequisite**

- Python: 3.6 or above

- Scrapy


**2. Output**
Example:

```
url: https://www.cvedetails.com//cve/CVE-2014-0347/

title:CVE-2014-0347

vendor:	Websense

said:	CVE-2014-0347

publishedDate: 4/12/2014	

modifiedDate: 4/14/2014	

description:The Settings module in Websense Triton Unified Security Center 7.7.3 before Hotfix 31, Web Filter 7.7.3 before Hotfix 31, Web Security 7.7.3 before Hotfix 31, Web Security Gateway 7.7.3 before Hotfix 31, and Web Security Gateway Anywhere 7.7.3 before Hotfix 31 allows remote authenticated users to read cleartext passwords by replacing type="password" with type="text" in an INPUT element in the (1) Log Database or (2) User Directories component.

severity:	Low

cve: CVE-2014-0347

affectedProducts:	TritonUnifiedSecurityCenter(7.7.3),TritonWebFilter(7.7.3),TritonWebSecurity(7.7.3),TritonWebSecurityGateway(7.7.3),TritonWebSecurityGatewayAnywhere(7.7.3)

workaround:	

solution:
```
