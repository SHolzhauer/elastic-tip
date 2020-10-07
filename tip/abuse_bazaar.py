import requests
import hashlib
from time import time

class URLhaus:

    def __init__(self):
        self.index = "tip-urlhaus"
        self._raw_threat_intel = None
        self._threat_intel = []
        self._retrieved = None

    def run(self):
        print("HI")
        self._download()
        self._parse()
        self._index()

    def _download(self):
        self._retrieved = time()
        response = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/")
        if response.status_code is 200:
            self._raw_threat_intel = response.text

    def _parse(self):
        for line in self._raw_threat_intel.split("\n"):
            if line[:1] is "#":
                print(line)
            else:
                docid = hashlib.sha1(line.encode()).hexdigest()
                split_line = line.split('","')
                try:
                    intel = {
                        "event": {
                            "module": "tip",
                            "dataset": "tip.abuse_bazaar.urlhaus"
                        },
                        "intel": {
                            "hash": {
                                "sha1": docid
                            },
                            "retrieved": self._retrieved,
                            "module": "URLhaus"
                        },
                        "urlhaus": {
                            "id": split_line[0].strip('"'),
                            "created": split_line[1],
                            "ioc": split_line[2],
                            "status": split_line[3],
                            "threat": split_line[4],
                            "tags": split_line[5].split(","),
                            "reference": split_line[6],
                            "reporter": split_line[7].strip('\r').strip('"')
                        }
                    }
                except IndexError:
                    pass
                else:
                    self._threat_intel.append(intel)

    def _index(self):
        print("Would index {} documents into the {} index".format(len(self._threat_intel), self.index))