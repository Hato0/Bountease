import subprocess, masscan, nmap, requests, re
from time import sleep


class activeScan:
    def __init__(self, isFull, targetIP=[], targetDomain=[], topXPort=100, reqLimit=None ,verify=True, userAgent=None):
        self.targetIP = targetIP
        self.targetDomain = targetDomain
        self.domain = {}
        self.ip = {}
        self.secHeaders = {}
        self.wafData = {}
        self.directoryListing = {}
        self.isFull = isFull
        with open('tmpFiles/activeIPScan.txt', 'w+') as wFile:
            for item in self.targetIP:
                wFile.write(item)
                self.ip[item] = {}
        with open('tmpFiles/activeDomainScan.txt', 'w+') as wFile:
            for item in self.targetDomain:
                wFile.write(item)
                self.domain[item] = []
                self.secHeaders[item] = {}
                self.wafData[item] = []
                self.directoryListing[item] = {}
        self.reqLimit = reqLimit
        self.topXPort = topXPort
        self.verify = verify
        self.userAgent = userAgent
        self.isAPI = []

    def massScan(self):
        mas = masscan.PortScanner() 
        nm = nmap.PortScanner()
        if self.isFull:
            if self.reqLimit:
                mas.scan(self.targetIP[0], ports='0-65535 ', arguments=f'--rate {self.reqLimit} -iL activeIPScan.txt')
            else:
                mas.scan(self.targetIP[0], ports='0-65535 ', arguments=f'-iL activeIPScan.txt')
        else:
            if self.reqLimit:
                mas.scan(self.targetIP[0], arguments=f'--rate {self.reqLimit} -iL activeIPScan.txt --top-ports {self.topXPort}')
            else:
                mas.scan(self.targetIP[0], arguments=f'-iL activeIPScan.txt --top-ports {self.topXPort}')
        scanResult = mas.scan_result
        for ip in scanResult["scan"]:
            for port in scanResult["scan"][ip]["tcp"]:
                if self.reqLimit:
                    nm.scan(ip, port, f"–max-rate {self.reqLimit}")
                else:
                    nm.scan(ip, port)
                nmapAdditionalData = nm.csv().split(";")
                self.ip[ip] = {port: {
                    "name": nmapAdditionalData[3],
                    "state": nmapAdditionalData[4],
                    "product": nmapAdditionalData[5],
                    "Version": nmapAdditionalData[8],
                    "AdditionalInformation": nmapAdditionalData[6]
                }}
            for port in scanResult["scan"][ip]["udp"]:
                if self.reqLimit:
                    nm.scan(ip, port, f"–max-rate {self.reqLimit}")
                else:
                    nm.scan(ip, port)
                nmapAdditionalData = nm.csv().split(";")
                self.ip[ip] = {port: {
                    "name": nmapAdditionalData[3],
                    "state": nmapAdditionalData[4],
                    "product": nmapAdditionalData[5],
                    "Version": nmapAdditionalData[8],
                    "AdditionalInformation": nmapAdditionalData[6]
                }}

    def vhostEnum(self):
        for domain in self.targetDomain:
            UA = self.userAgent if self.userAgent else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'
            proc = subprocess.call(["gobuster", "vhost", "--useragent", UA, "--wordlist", "wordlist/vhost.txt", "--url", domain], stdout=subprocess.PIPE, universal_newlines=True)
            output = proc.stdout
            regex = f"(([a-z0-9]+[.])*{domain})"
            vhostTemp = re.findall(regex, output)
            for match in vhostTemp:
                if match[0] not in self.domain[domain]:
                    self.domain[domain].append(match[0])

    def subDomainEnum(self):
        for domain in self.targetDomain:
            proc = subprocess.call(["gobuster", "dns", "-d", domain, "--wordlist", "wordlist/subdomains.txt", "-i", "--wildcard"], stdout=subprocess.PIPE, universal_newlines=True)
            output = proc.stdout
            regex = f"(([a-z0-9]+[.])*{domain})"
            vhostTemp = re.findall(regex, output)
            for match in vhostTemp:
                if match[0] not in self.domain[domain]:
                    self.domain[domain].append(match[0])

    def apiDiscovery(self):
        for domain in self.targetDomain:
            testValue = "198uhjdsbiyufgh1"
            if 'https' not in domain or 'http' not in domain:
                domainFull = "http://"+domain
            else: 
                domainFull = domain
            userAgent = self.userAgent if self.userAgent else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'
            headers = {"User-Agent": userAgent}
            resp = requests.get(domainFull+"/"+testValue, headers=headers, verify=self.verify)
            baseline = len(resp.text)-(len(testValue)*resp.text.count(testValue))
            if domain.split('.')[0] == 'api':
                self.isAPI(domain)
            else:
                if self.userAgent:
                    headers = {'User-Agent': self.userAgent} 
                else:
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'}
                resp = requests.get(domainFull+'/api', headers=headers, verify=self.verify)
                if resp.status_code != 404 and (len(resp.text)-(len(testValue)*resp.text.count(testValue))) != baseline:
                    self.isAPI(domain)
                    
    def securityHeaders(self):
        securityHeaders = ["x-xss-protection", "strict-transport-security", "x-frame-options", "x-content-type-options", "content-security-policy", "public-key-pins", "x-permitted-cross-domain-policies", "referrer-policy"]
        for domain in self.targetDomain:
            if 'https' not in domain or 'http' not in domain:
                domainFull = "http://"+domain
            else: 
                domainFull = domain
            userAgent = self.userAgent if self.userAgent else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'
            headers = {"User-Agent": userAgent}
            res = requests.get(domainFull, headers=headers)
            headers = res.headers
            for header in securityHeaders:
                if header in headers:
                    self.secHeaders[domain][header] = True
                else:
                    self.secHeaders[domain][header] = False
            if self.reqLimit:
                sleep(1/self.reqLimit)
    
    def detectWAF(self):
        for domain in self.domain:
            if 'https' not in domain or 'http' not in domain:
                domainFull = "http://"+domain
            else: 
                domainFull = domain
            userAgent = self.userAgent if self.userAgent else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'
            headers = {"User-Agent": userAgent}
            proc = subprocess.call(["wafw00f", domainFull, "-H", headers, "-f", "text"], stdout=subprocess.PIPE, universal_newlines=True)
            output = proc.stdout
            if 'No WAF detected' in output:
                continue
            else:
                regex = "is\sbehind\s([a-zA-Z-\s()0-9]*)\sWAF"
                WAFs = re.findall(regex, output)
                for waf in WAFs:
                    self.wafData[domain].append(waf)

    def directoryListingScan(self):
        for domain in self.targetDomain:
            protos = ["http://", "https://"]
            extensions = ["\.html", "\.php", "\.js", "\.env", "\.DS_Store", "\.log", "\.py", "\.json", "\.properties", "\.pem", "\.xml", "\.yml" , "\.yaml" ,"\.ts"]
            if 'https' not in domain or 'http' not in domain:
                domainFull = "http://"+domain
            else: 
                domainFull = domain
            userAgent = self.userAgent if self.userAgent else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'
            headers = {"User-Agent": userAgent}
            res = requests.get(domainFull, headers=headers)
            test4DirList = []
            for proto in protos:
                for extension in extensions:
                    regex = f"{proto}{domain}[a-zA-Z0-9/_-]{extension}"
                    localUrls = re.findall(regex, res.text)
                    for url in localUrls:
                        old = "/"
                        new = ""
                        test4DirList.append((url[::-1].replace(old[::-1],new[::-1], 1))[::-1])
            for url in test4DirList:
                res = requests.get(url, headers=headers)
                if "Index of /" in res.text or "[To Parent Directory]" in res.text:
                    self.directoryListing[domain]["isVulnerable"] = True
                    if not self.directoryListing[domain]["VulnerableEndpoint"]:
                        self.directoryListing[domain]["VulnerableEndpoint"] = []
                    self.directoryListing[domain]["VulnerableEndpoint"].append(url)
                if self.reqLimit:
                    sleep(1/self.reqLimit)