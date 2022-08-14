import requests, re, urllib3, json, html
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SocialHunt:
    def __init__(self, target, linkedinCookie=None, dorksMax=10, verify=True):
        self.target = []
        self.employee = {}
        self.mailFormat = {}
        for item in target:
            self.target.append(item)
            self.employee[item] = {}
            self.mailFormat[item] = []
        self.linkedinCookie = linkedinCookie
        self.dorksMax = dorksMax
        self.verify = verify

    def getEmployee(self):
        for domain in self.target:
            companyName = domain.split('.')[0]
            for i in range(0,self.dorksMax+1):
                url = f"https://www.google.com/search?q=site%3Alinkedin.com+{companyName}+-inurl%3A{companyName}&start={i*10}"
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'}
                resp = requests.get(url, headers=headers,verify=self.verify)
                regex = '.*https:\/\/.{3}linkedin\.com\/in\/([a-zA-Z0-9-]*)'
                companyEmployees = re.findall(regex, resp.text)
                for employe in companyEmployees:
                    if employe not in self.employee[domain]:
                        self.employee[domain][employe] = []

    def getLinkedinInfo(self):
        if self.linkedinCookie:
            for domain in self.target:
                for employee in self.employee[domain]:
                    url = f"https://www.linkedin.com/in/{employee}/overlay/contact-info/"
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'}
                    cookies = {'li_at': self.linkedinCookie}
                    resp = requests.get(url, headers=headers, cookies=cookies, verify=self.verify)
                    regex = '.*Twitter.*'
                    data = re.findall(regex, resp.text)
                    if len(data) > 0:
                        data = json.loads(html.unescape(data[0]))
                        for element in data["data"]:
                            if data["data"][element] and "urn:li:fs_contactinfo" not in data["data"][element] and data["data"][element] != "com.linkedin.voyager.identity.profile.ProfileContactInfo":
                                self.employee[domain][employee].append(data["data"][element])

    def getEmailFormat(self):
        for domain in self.target:
            url = f"https://www.google.com/search?q={domain}+email"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0'}
            resp = requests.get(url, headers=headers,verify=self.verify)
            regex = '(([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5}))'
            mailFormat = re.findall(regex, resp.text)
            for mail in mailFormat:
                if mail[0] not in self.mailFormat[domain]:
                    self.mailFormat[domain].append(mail[0])