import scrapy
import re


class DataSpider(scrapy.Spider):
    name = 'AntiVirus'
    basic_url = 'https://www.cvedetails.com/'
    start_urls = [
        basic_url + "product/21801/Oracle-Mysql.html?vendor_id=93",
        basic_url + "vendor/1305/Solarwinds.html",
        basic_url + "product/251/Microsoft-Sql-Server.html?vendor_id=26",
        basic_url + "vendor/4398/Websense.html",
        "https://www.cvedetails.com/product/36038/Radware-Alteon.html?vendor_id=9876",
        "https://www.cvedetails.com/product/15031/Google-Chrome.html?vendor_id=1224",
        "https://www.cvedetails.com/product/576/IBM-Websphere-Application-Server.html?vendor_id=14",
        "https://www.cvedetails.com/vulnerability-list/vendor_id-1511/Infoblox.html",
        "https://www.cvedetails.com/vendor/12010/Mariadb.html",
        "https://www.cvedetails.com/vendor/13968/Mobileiron.html",
        "https://www.cvedetails.com/product/18230/Python-Python.html?vendor_id=10210",
        "https://www.cvedetails.com/vendor/10001/Radvision.html",
        "https://www.cvedetails.com/product/32011/Thycotic-Secret-Server.html?vendor_id=15429",
        "https://www.cvedetails.com/vendor/215/Trend-Micro.html",
        "https://www.cvedetails.com/product/11613/Winpcap-Winpcap.html?vendor_id=6910",
    ]
    custom_settings = {
        'FEED_EXPORT_FIELDS': ["url", "title", "vendor", "said", "publishedDate", "modifiedDate", "description",
                               "severity", "cve", "affectedProducts", "workaround", "solution"], }

    def parse(self, response):
        basic_url = 'https://www.cvedetails.com'
        trs = response.xpath("//div[@id='contentdiv']/table[@class='stats']/tr")[1:]
        for tr in trs:
            link = tr.xpath("th")[0].xpath("a/@href").extract_first()
            if link != None:
                yield response.follow(basic_url+link, self.cveparse)
        if len(trs)==0:
            yield response.follow(response.url, self.cveparse)

    def cveparse(self, response):
        basic_url = 'https://www.cvedetails.com/'
        trs = response.xpath("//div[@id='searchresults']/table[@id='vulnslisttable']/tr[@class='srrowns']")
        for tr in trs:
            try:
                link = tr.xpath("td")[1].xpath("a/@href").extract_first()
                if link != None:
                    yield response.follow(basic_url + link, self.vulparse)
            except:
                print("link %s scrap fails", str(response.url))

    def vulparse(self, response):
        vendors = []
        affected_products = []
        link = response.url
#part for severity
        severity_score = response.xpath("//table[@id='cvssscorestable']/tr/td/div/text()").extract_first()
        severity = self.handle_severity(severity_score)

#part for CVE
        CVE = response.xpath("//td[@id='cvedetails']/h1/a/text()").extract_first()
#part for description
        raw_description = response.xpath("//td[@id='cvedetails']/div/text()").extract()
        description = self.simplify_description(raw_description)
#part for publishe date and modify date
        Date = response.xpath("//td[@id='cvedetails']/div[@class='cvedetailssummary']/span/text()").extract_first()
        publish_date = re.findall(r'(\d+-\d+-\d+)', re.sub('\s+','',str(Date)))[0]
        last_update_date = re.findall(r'(\d+-\d+-\d+)', re.sub('\s+','',str(Date)))[1]
# part for products and vendors
        parse_products = response.xpath("//table[@id='vulnprodstable']/tr")[1:]
        for parse_product in parse_products:
            vendor = parse_product.xpath("td/a")[0].css("::text").extract_first()
            vendors.append(vendor + ',') if (vendor + ',') not in vendors else None
            affected_product = parse_product.xpath("td/a")[1].css("::text").extract_first()
            if affected_product[0] == '[':
                affected_product=parse_product.xpath("td/a/@title").extract()[1].split()[-1]
            affected_version = parse_product.xpath("td")[4].css("::text").extract_first()
            update = parse_product.xpath("td")[5].css("::text").extract_first()
            edition = parse_product.xpath("td")[6].css("::text").extract_first()
            if update:
                affected_version = affected_version+update
            if edition:
                affected_version = affected_version+edition
            affected_version = re.sub("~",'',affected_version)
            if str(affected_product) not in affected_products:
                if len(affected_products) ==0:
                    affected_products.append(str(affected_product))
                    affected_products.append('(')
                else:
                    if affected_products[-1][-1]==',':
                        affected_products[-1] = affected_products[-1][:-1]
                    affected_products.append('),')
                    affected_products.append(str(affected_product))
                    affected_products.append('(')
                affected_products.append(affected_version+',')
            else:
                affected_products.append(affected_version+',')
        additional_vendors = response.xpath("//div[@id='addvendsuppdata']/table/tr/td/a/text()").extract()
        if additional_vendors:
            for additional_vendor in additional_vendors:
                vendors.append(additional_vendor+',')
        vendors = self.sub_blank(vendors)
        affected_products = self.formatting(self.sub_blank(affected_products))+')'

        yield {
            'title':self.formatting(CVE),
            'url': self.formatting(link),
            'severity': self.formatting(severity),
            'cve': self.formatting(CVE),
            'said':self.formatting(CVE),
            'publishedDate': self.formatting(publish_date),
            'modifiedDate': self.formatting(last_update_date),
            'vendor': self.formatting(vendors),
            'affectedProducts': self.formatting(affected_products),
            'description':self.formatting(description),
            'workaround': None,
            'solution': None
        }


    def sub_blank(self, contents):
        content = ''.join(contents)
        content = re.sub('\s+', '', content)
        content = re.sub('\t', '', content)
        content = re.sub('\n', '', content)
        return content

    def handle_severity(self,content):
        if int(content[0])==0:
            severity = 'Information'
        elif int(content[0])<4:
            severity = 'Low'
        elif int(content[0])<7:
            severity = 'Medium'
        elif int(content[0])<9:
            severity = 'High'
        else:
            severity = 'Critical'
        return severity

    def simplify_description(self, description):
        description = ''.join(description)
        description = re.sub('\t', '', str(description))
        description = re.sub('\n', ' ', str(description))
        return description

    def formatting(self,content):
        if isinstance(content,list):
            content = ''.join(content).strip()
        else:
            content = content.strip()
        if content[-1] is ',':
            content = content[:-1]
        return content
