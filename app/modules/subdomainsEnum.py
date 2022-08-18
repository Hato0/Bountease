import requests, re, urllib3, bs4
from time import sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SubHunt:
    def __init__(self, target, dorksMax=10, apiVT=None ,verify=True):
        self.target = []
        self.subdomain = {}
        self.hostRecords = {}
        self.txtRecords = {}
        self.mxRecords = {}
        for item in target:
            self.target.append(item)
            self.subdomain[item] = []
            self.hostRecords[item] = []
            self.txtRecords[item] = []
            self.mxRecords[item] = []
        self.dorksMax = dorksMax
        self.apiVT = apiVT
        self.verify = verify

    def getCRT(self):
        for domain in self.target:
            url = "https://crt.sh/?q=" + domain
            resp = requests.get(url, verify=self.verify)
            regex = f"(([a-z0-9]+[.])*{domain})"
            domainTemp = re.findall(regex, resp.text)
            for match in domainTemp:
                if match[0] not in self.subdomain[domain]:
                    self.subdomain[domain].append(match[0])

    def getWayback(self):
        for domain in self.target:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
            resp = requests.get(url, verify=self.verify)
            regex = f"(https?:\/\/([a-z0-9]+\.)*{domain})"
            domainTemp = re.findall(regex, resp.text)
            rep = {'https://': '', 'http://': ''}
            rep = dict((re.escape(k), v) for k, v in rep.items())
            pattern = re.compile("|".join(rep.keys())) 
            for match in domainTemp:
                subDomain = pattern.sub(lambda m: rep[re.escape(m.group(0))], match[0])
                if subDomain not in self.subdomain[domain]:
                    self.subdomain[domain].append(subDomain)

    def getDorks(self):
        for domain in self.target:
            for i in range(0,self.dorksMax+1):
                url=f"https://www.google.com/search?client=firefox-b-d&q=site%3A*.{domain}&start={i*10}"
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0', 'referer':'https://www.google.com/'}
                resp = requests.get(url, headers=headers,verify=self.verify)
                regex = f"(([a-z0-9]+[.])*{domain})"
                domainTemp = re.findall(regex, resp.text)
                for match in domainTemp:
                    if match[0] not in self.subdomain[domain]:
                        self.subdomain[domain].append(match[0])
                sleep(0.5)

    def getDnsdumpster(self):
        for domain in self.target:
            res = requests.get("https://dnsdumpster.com")
            csrf = res.headers["Set-Cookie"].split('=')[1]
            csrf = csrf.split(';')[0]
            regex = "csrfmiddlewaretoken\"\svalue=\"([a-zA-Z0-9]*)\""
            csrfMiddle = re.findall(regex, res.text)
            data = {'csrfmiddlewaretoken': {csrfMiddle[0]}, 'targetip': {domain}, 'user': 'free'}
            cookies = {"csrftoken": csrf}
            headers = {'Origin': 'https://dnsdumpster.com', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0', 'Referer': 'https://dnsdumpster.com/'}
            res = requests.post("https://dnsdumpster.com", data=data, cookies=cookies, headers=headers)
            soupData = bs4.BeautifulSoup(res.text, 'html.parser')
            tableData = soupData.findAll('table')
            for element in tableData[1].findAll('tr'):
                temp = []
                for data in element.findAll('td'):
                    data = data.text
                    data = data.replace('\n','')
                    temp.append(data)
                self.mxRecords[domain].append(temp)
            for element in tableData[2].findAll('td'):
                self.txtRecords[domain].append(element.text)
            for element in tableData[3].findAll('tr'):
                element = element.text
                element = element.replace('\n','')
                temp = []
                extractIps = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", element)
                regex = f"(([a-z0-9]+\.)*{domain})"
                domainTemp = re.findall(regex, element)
                for match in domainTemp:
                    alreadySeen = False
                    for elem in self.hostRecords[domain]:
                        if match[0] in elem:
                            alreadySeen = True
                    if not alreadySeen:
                        temp.append(match[0])
                for match in extractIps:
                    if match[-2:] != '.0' and match not in temp:
                        temp.append(match)
                if len(temp) != 0 :
                    if len(self.hostRecords[domain]) == 0 and not alreadySeen:
                        if len(temp) == 2:
                            if temp[1] in temp[0]:
                                temp[0] = temp[0].split(temp[1])[0]
                        self.hostRecords[domain].append(temp)
                    else:
                        if not alreadySeen:
                            if len(temp) == 2:
                                if temp[1] in temp[0]:
                                    temp[0] = temp[0].split(temp[1])[0]
                            self.hostRecords[domain].append(temp)