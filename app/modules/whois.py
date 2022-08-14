from ipwhois import IPWhois
import socket

class Whois:
    def __init__(self, target):
        self.target = []
        self.whoisData = {}
        self.targetIP = {}
        for item in target:
            self.target.append(item)
            self.whoisData[item] = []
            self.targetIP[item] = []

    def getWhois(self):
        for domainData in self.targetIP:
            for IP in self.targetIP[domainData]:
                data = IPWhois(IP)
                resp = data.lookup_rdap()
                if resp not in self.whoisData[domainData]:
                    self.whoisData[domainData].append(resp)

    def getReverseDNS(self): 
        for domain in self.target:
            hostIp = socket.gethostbyname(domain)
            if hostIp not in self.targetIP[domain]:
                self.targetIP[domain].append(hostIp)