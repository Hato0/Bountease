import requests, urllib3
from threading import Thread

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class S3Hunt:
    def __init__(self, target, thread=20, verify=True):
        self.target = []
        self.s3Buckets = {}
        self.wordlist = []
        for item in target:
            self.target.append(item)
            self.s3Buckets[item] = []
        self.thread = thread
        self.verify = verify

    def getBucket(self, wordlist):
            for name in self.target:
                target = name
                name = name.split('.')[0]
                for test in wordlist: 
                    test = test.split('\n')[0]
                    r = requests.head(f"https://{name}-{test}.s3.amazonaws.com")
                    if r.status_code != 404:
                        self.s3Buckets[target].append(f"Bucket found : {name}-{test}")
                    r = requests.head(f"https://{name}{test}.s3.amazonaws.com")
                    if r.status_code != 404:
                        self.s3Buckets[target].append(f"Bucket found : {name}{test}")

    def launchBucketRecon(self):
        with open('wordlist/s3buckets.txt', 'r') as s3list:
            words = s3list.readlines()
        partialWordlist = []
        totalWords = len(words)
        wordlist = []
        index = 0
        for word in words:
            if index % (totalWords // self.thread) == 0 and index != 0:
                wordlist.append(partialWordlist)
                partialWordlist = []
                partialWordlist.append(word.strip('\n'))
                index += 1
            else:
                partialWordlist.append(word.strip('\n'))
                index += 1
        threads = [Thread(target=self.getBucket, args=(partWordlist,)) for partWordlist in wordlist]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()