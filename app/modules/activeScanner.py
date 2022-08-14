import subprocess, masscan, nmap, requests, re


class activeScan:
    def __init__(self, isFull, targetIP=[], targetDomain=[], topXPort=100, reqLimit=3 ,verify=True, userAgent=None):
        self.targetIP = targetIP
        self.targetDomain = targetDomain
        self.domain = {}
        self.ip = {}
        self.isFull = isFull
        with open('tmpFiles/activeIPScan.txt', 'w') as wFile:
            for item in self.targetIP:
                wFile.write(item)
                self.ip[item] = {}
        with open('tmpFiles/activeDomainScan.txt', 'w') as wFile:
            for item in self.targetDomain:
                wFile.write(item)
                self.domain[item] = []
        self.reqLimit = reqLimit
        self.topXPort = topXPort
        self.verify = verify
        self.userAgent = userAgent
        self.isAPI = []

    def massScan(self):
        mas = masscan.PortScanner() 
        nm = nmap.PortScanner()
        if self.isFull:
            mas.scan(self.targetIP[0], ports='0-65535 ', arguments=f'--rate {self.reqLimit} -iL activeIPScan.txt')
        else:
            mas.scan(self.targetIP[0], arguments=f'--rate {self.reqLimit} -iL activeIPScan.txt --top-ports {self.topXPort}')
        scanResult = mas.scan_result
        for ip in scanResult["scan"]:
            for port in scanResult["scan"][ip]["tcp"]:
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
            UA = self.userAgent if self.userAgent else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'
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
            resp = requests.get(domain+testValue, verify=self.verify)
            baseline = len(resp.text)-(len(testValue)*resp.text.count(testValue))
            if domain.split('.')[0] == 'api':
                self.isAPI(domain)
            else:
                if self.userAgent:
                    headers = {'User-Agent': self.userAgent} 
                else:
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'}
                resp = requests.get(domain+'/api', headers=headers, verify=self.verify)
                if resp.status_code != 404 and (len(resp.text)-(len(testValue)*resp.text.count(testValue))) != baseline:
                    self.isAPI(domain)
                    



