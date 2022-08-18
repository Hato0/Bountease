#!/usr/bin/env python3

from encodings import normalize_encoding
from modules.subdomainsEnum import SubHunt
from modules.whois import Whois
from modules.s3Enum import S3Hunt
from modules.socialEng import SocialHunt
from modules.activeScanner import activeScan
import yaml, argparse, re, json

def createReport(obj, mode):
    global outputPathList
    global targets
    if mode == 'passiv':
        for target in targets:
            with open(outputPathList[target], "a") as report:
                report.write("## Passive Enumeration Summary \n\n")
                for fonct in obj:
                    if type(fonct).__name__ == "SubHunt":
                        report.write(f"#### Subdomain data\n")
                        report.write(f"|Subdomain|Comment|Checked ?|\n|:-|:-|:-:|\n")
                        for item in fonct.subdomain[target]:
                            seen = False
                            found = ""
                            for association in fonct.hostRecords[target]:
                                if item in association[0]:
                                    seen = True
                                    found = association[1]
                            if not seen:
                                report.write(f"|{item}||[ ]|\n")
                            else:
                                report.write(f"|{item}|Associate IP : {found}|[ ]|\n")
                        if len(fonct.txtRecords[target]) != 0:
                            report.write(f"\n#### TXT Records\n")
                            report.write(f"|Data|Interesting ?|\n|:-|:-:|\n")
                            for item in fonct.txtRecords[target]:
                                report.write(f"|{item}|[ ]|\n")
                        else:
                            report.write(f"\n#### TXT Records\nNo data found\n")
                        if len(fonct.mxRecords[target]) != 0:
                            report.write(f"\n#### MX Records\n")
                            report.write(f"|Data|Interesting ?|\n|:-|:-:|\n")
                            for item in fonct.mxRecords[target]:
                                for data in item:
                                    report.write(f"|{data}|[ ]|\n")
                        else:
                            report.write(f"\n#### MX Records\nNo data found\n")
                    if type(fonct).__name__ == "S3Hunt":
                        report.write(f"\n#### S3 Buckets\n")
                        if len(fonct.s3Buckets[target]) != 0:
                            report.write(f"|S3 Buckets|Comment|Checked ?|\n|:-|:-|:-:|\n")
                            for item in fonct.s3Buckets[target]:
                                report.write(f"|{item}||[ ]|\n")
                        else:
                            report.write(f"No data found\n")
                    if type(fonct).__name__ == "Whois":
                        report.write(f"\n#### Whois data\n")
                        if len(fonct.whoisData[target]) != 0:
                            report.write(f"|IP|Comment|Interesting ?|\n|:-|:-|:-:|\n")
                            cnt = 0
                            for item in fonct.targetIP[target]:
                                report.write(f"|{item}|{fonct.whoisData[target][cnt]}|[ ]|\n")
                                cnt += 1
                        else:
                            report.write(f"No data found\n")
                    if type(fonct).__name__ == "SocialHunt":
                        report.write(f"\n#### Company OSINT data\n")
                        if len(fonct.mailFormat[target]) != 0:
                            report.write("Mail format found :\n")
                            for format in fonct.mailFormat[target]:
                                report.write(f"* {format}\n")
                        if len(fonct.employee[target]) != 0:
                            report.write(f"\n|Employe name|Employee Data|Interesting ?|\n|:-|:-|:-:|\n")
                            for item in fonct.employee[target]:
                                employeeData = ""
                                for data in fonct.employee[target][item]:
                                    employeeData += data
                                report.write(f"|{item}|{employeeData}|[ ]|\n")
                        else:
                            report.write(f"No data found\n")
    if mode == 'activ':
        for target in targets:
            with open(outputPathList[target], "a") as report:
                report.write("## Active Enumeration Summary \n\n")
                report.write(f"#### Scan data\n")
                report.write(f"|IP Scan|Scan Data|Comment|Checked ?|\n|:-|:-|:-|:-:|\n")
                if len(obj.ip) != 0:
                    for item in obj.ip[target]:
                        scanData = ""
                        for port in item:
                            scanData += f"""Port {port}:\n
                                    * Name: {port["name"]}\n
                                    * State: {port["state"]}\n
                                    * Product: {port["product"]}\n
                                    * Version: {port["Version"]}\n
                                    * Additional Information: {port["AdditionalInformation"]}\n\n
                                    """
                        report.write(f"|{item}|{scanData}||[ ]|\n")
                else:
                    report.write(f"\nNo data found\n")

                report.write(f"#### Subdomain data\n")
                report.write(f"|Subdomain|Comment|Checked ?|\n|:-|:-|:-:|\n")
                if len(obj.domain) != 0 :
                    for item in obj.domain[target]:
                            report.write(f"|{item}||[ ]|\n")
                else:
                    report.write(f"\nNo data found\n")
                
                report.write(f"#### API Endpoints data\n")
                report.write(f"|Endpoint|Comment|Checked ?|\n|:-|:-|:-:|\n")
                if len(obj.isAPI) != 0 :
                    for item in obj.isAPI:
                            report.write(f"|{item}||[ ]|\n")
                else:
                    report.write(f"\nNo data found\n")
                
                report.write(f"#### Security Headers data\n")
                report.write(f"|Website|Headers|Comment|Checked ?|\n|:-|:-|:-|:-:|\n")
                if len(obj.secHeaders) != 0:
                    for website in obj.secHeaders:
                        headerData = ""
                        for header in website:
                            comment = "Present" if header else "Absent"
                            headerData += f"""{header}: {comment}\n
                                    """
                        report.write(f"|{website}|{headerData}||[ ]|\n")
                else:
                    report.write(f"\nNo data found\n")

                report.write(f"#### WAF data\n")
                report.write(f"|Website|WAF Detected|Comment|Checked ?|\n|:-|:-|:-|:-:|\n")
                if len(obj.wafData) != 0:
                    for website in obj.wafData:
                        WafData = ""
                        for wafSign in website:
                            WafData += f"{wafSign}\n\n"
                        report.write(f"|{website}|{Waf}||[ ]|\n")
                else:
                    report.write(f"\nNo data found\n")

                report.write(f"#### Directory Listing Scan\n")
                report.write(f"|Website|Vulnerable URL|Comment|Checked ?|\n|:-|:-|:-|:-:|\n")
                if len(obj.directoryListing) != 0:
                    for website in obj.directoryListing:
                        VulnerableURLs = ""
                        if website["isVulnerable"]:
                            for endpoint in website["VulnerableEndpoint"]:
                                VulnerableURLs += f"{endpoint}\n"
                            report.write(f"|{website}|{VulnerableURLs}||[ ]|\n")
                else:
                    report.write(f"\nNo data found\n")

def passScan(targets, dorkMax, verify, doCRT, doWayback, doDorks,  doDnsdumpster, 
                doS3, s3Thread, doWhois, doSocial, linkCook):
    subDomainHunt = SubHunt(targets, dorksMax=dorkMax, verify=verify)
    enumDone = []
    if doCRT:
        subDomainHunt.getCRT()
    if doWayback:
        subDomainHunt.getWayback()
    if doDorks:
        subDomainHunt.getDorks()
    if doDnsdumpster:
        subDomainHunt.getDnsdumpster()
    if doCRT or doWayback or doDorks or doDnsdumpster:
        enumDone.append(subDomainHunt)
    if s3Thread:
        s3Hunt = S3Hunt(targets, verify=verify)
    else:
        s3Hunt = S3Hunt(targets, thread=s3Thread, verify=verify)
    if doS3:
        s3Hunt.launchBucketRecon()
        enumDone.append(s3Hunt)
    targetWhois = []
    for url in subDomainHunt.subdomain:
        targetWhois.append(url)
    for domain in targets:
        targetWhois.append(url)
    whoisHunt = Whois(targetWhois)
    if doWhois:
        whoisHunt.getReverseDNS()
        whoisHunt.getWhois()
        enumDone.append(whoisHunt)
    if linkCook:
        socialHunt = SocialHunt(targets, linkedinCookie=linkCook, dorksMax=dorkMax, verify=verify)
    else:
        socialHunt = SocialHunt(targets, dorksMax=dorkMax, verify=verify)
    if doSocial:
        socialHunt.getEmployee()
        if linkCook:
            socialHunt.getLinkedinInfo()
        socialHunt.getEmailFormat()
        enumDone.append(socialHunt)
    createReport(enumDone, "passiv")

def actScan(targetIP, targetDomain, doMassScan, doVhostEnum, doApiDisco, doSubEnum, 
            doSecuHeader, doWafEnum, doDirList,isFull, topXPort, reqLimit, 
            verify, userAgent):
    actHunt = activeScan(isFull, targetIP, targetDomain, topXPort, reqLimit, verify, userAgent)
    if doMassScan:
        actHunt.massScan()
    if doVhostEnum:
        actHunt.vhostEnum()
    if doSubEnum:
        actHunt.subDomainEnum()
    if doApiDisco:
        actHunt.apiDiscovery()
    if doSecuHeader:
        actHunt.securityHeaders()
    if doWafEnum:
        actHunt.detectWAF()
    if doDirList:
        actHunt.directoryListingScan()
    createReport(actHunt, "activ")


def hybridScan(targets, targetIP, dorkMax, verify, doCRT, doWayback, doDorks,  doDnsdumpster, 
               doS3, s3Thread, doWhois, doSocial, linkCook, doMassScan, doVhostEnum, 
               doApiDisco, doSubEnum, doSecuHeader, doWafEnum, doDirList, isFull, 
               topXPort, reqLimit, userAgent):
    passScan(targets, dorkMax, verify, doCRT, doWayback, doDorks,  doDnsdumpster, doS3, s3Thread, doWhois, 
    doSocial, linkCook)
    actScan(targetIP, targets, doMassScan, doVhostEnum, doApiDisco, doSubEnum, doSecuHeader, doWafEnum, 
    doDirList, isFull, topXPort, reqLimit, userAgent)




if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", help="Recon mode (Active, Passive, Hybrid)", required=True)
    parser.add_argument("-t", "--targets", help="Targets to scan (list)", required=True)
    parser.add_argument("-c", "--config", help="Config file", required=True)
    parser.add_argument("-o", "--output", help="Output path", required=True)
    args = parser.parse_args()

    targets = json.loads(args.targets)
    configPath = args.config
    outputPath = args.output
    mode = args.mode
    outputPathList = {}
    for target in targets:
        outputPathList[target] = ""
    if len(targets) > 1:
        for target in targets:
            nameTarget = target.replace('.', '_')
            path = outputPath.split('.')[0] + f"-{nameTarget}." + outputPath.split('.')[1]
            outputPathList[target] = path
            with open(path, "w") as report:
                Title = f"# Report for target(s): {target}"
                report.write(Title + "\n")
    else:
        with open(outputPath, "w") as report:
                Title = "# Report for target(s): "
                for target in targets:
                    Title += target
                report.write(Title + "\n")
        outputPathList[targets[0]] = outputPath

    with open(configPath, 'r') as configFile:
        cfg = yaml.safe_load(configFile)
    
    verify = cfg["Global"]["verify"]
    reqLimit = cfg["Global"]["reqLimit"]
    userAgent = cfg["Global"]["userAgent"]

    doCRT =  cfg["Passiv"]["doCRT"]
    doWayback = cfg["Passiv"]["doWayback"]
    doDorks = cfg["Passiv"]["doDorks"]
    doDnsdumpster = cfg["Passiv"]["doDnsdumpster"]
    doS3 = cfg["Passiv"]["doS3"]
    s3Thread = cfg["Passiv"]["s3Thread"]
    doWhois = cfg["Passiv"]["doWhois"]
    doSocial = cfg["Passiv"]["doSocial"]
    linkCook = cfg["Passiv"]["linkCook"]
    maxDorks = cfg["Passiv"]["maxDorks"]

    doMassScan = cfg["Activ"]["doMassScan"]
    doVhostEnum = cfg["Activ"]["doVhostEnum"]
    doApiDisco = cfg["Activ"]["doApiDisco"]
    doSubEnum = cfg["Activ"]["doSubEnum"]
    doSecuHeader = cfg["Activ"]["doSecuHeader"]
    doWafEnum = cfg["Activ"]["doWafEnum"]
    doDirList = cfg["Activ"]["doDirList"]
    isFull = cfg["Activ"]["isFull"]
    topXPort = cfg["Activ"]["topXPort"]
    
    targetIP = []
    for target in targets:
        regex = "\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b"
        ipTest = re.findall(regex, target)
        if target in ipTest:
            targetIP.append(target)
    if mode == "Hybrid":
        hybridScan(targets, targetIP, maxDorks, verify, doCRT, doWayback, doDorks,  doDnsdumpster, 
               doS3, s3Thread, doWhois, doSocial, linkCook, doMassScan, doVhostEnum, 
               doApiDisco, doSubEnum, doSecuHeader, doWafEnum, doDirList, isFull, 
               topXPort, reqLimit, userAgent)
    if mode == "Active":
        actScan(targetIP, targets, doMassScan, doVhostEnum, doApiDisco, doSubEnum, 
            doSecuHeader, doWafEnum, doDirList,isFull, topXPort, reqLimit, 
            verify, userAgent)
    if mode == "Passive":
        passScan(targets, maxDorks, verify, doCRT, doWayback, doDorks,  doDnsdumpster, 
                doS3, s3Thread, doWhois, doSocial, linkCook)
