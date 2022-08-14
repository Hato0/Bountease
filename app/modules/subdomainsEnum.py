import requests, re, urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SubHunt:
    def __init__(self, target, dorksMax=10, apiVT=None ,verify=True):
        self.target = []
        self.subdomain = {}
        for item in target:
            self.target.append(item)
            self.subdomain[item] = []
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
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'}
                resp = requests.get(url, headers=headers,verify=self.verify)
                regex = f"(([a-z0-9]+[.])*{domain})"
                domainTemp = re.findall(regex, resp.text)
                for match in domainTemp:
                    if match[0] not in self.subdomain[domain]:
                        self.subdomain[domain].append(match[0])

    def getDnsdumpster(self):
        pass
