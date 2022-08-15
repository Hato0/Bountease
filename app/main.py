#!/usr/bin/env python3

from modules.subdomainsEnum import SubHunt
from modules.whois import Whois
from modules.s3Enum import S3Hunt
from modules.socialEng import SocialHunt
from modules.activeScanner import activeScan



if __name__ == "__main__":
    # test = SubHunt(["example.com"], dorksMax=20, verify=False)
    # test.getDnsdumpster()
    # test.getCRT()
    # test.getWayback()
    # test.getDorks()
    # print(test.subdomain)
    # test2 = Whois(["example.com"])
    # test2.getReverseDNS()
    # test2.getWhois()
    # print(test2.targetIP)
    # print(test2.whoisData)
    # test3 = S3Hunt(["example.com"], verify=False)
    # test3.launchBucketRecon()
    # test4 = SocialHunt(["example.com", "example2.com"], linkedinCookie="**REDACTED**", dorksMax=10, verify=False)
    # test4.getEmployee()
    # test4.getLinkedinInfo()
    # test4.getEmailFormat()
    # print(test4.mailFormat)
    # test5 = activeScan(False, targetIP=[], targetDomain=["example.com"], topXPort=100, reqLimit=3 ,verify=True, userAgent="Bountease")
    # test5.massScan()
    # test5.vhostEnum()
    # test5.apiDiscovery()
    # test5.subDomainEnum()
    # print(test5.isAPI, test5.domain, test5.ip)
    # test5.securityHeaders()
    # test5.detectWAF()
    # test5.directoryListingScan()
    print('Still in development ...')