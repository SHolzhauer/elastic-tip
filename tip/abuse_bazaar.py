from ioc import IOC
import requests
import hashlib
from time import time


class URLhaus:

    def __init__(self):
        self._raw_threat_intel = None
        self.iocs = []
        self._retrieved = None
        self._feed_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    def run(self):
        self._download()
        self._parse()

    def _download(self):
        self._retrieved = time()
        response = requests.get(self._feed_url)
        if response.status_code is 200:
            self._raw_threat_intel = response.text

    def _parse(self):
        for line in self._raw_threat_intel.split("\n"):
            if line[:1] is "#":
                print(line)
            else:
                split_line = line.split('","')
                try:
                    ioc = IOC(
                        ref=[split_line[6], self._feed_url],
                        value=split_line[2],
                        type="domain",
                        pname="URLhaus",
                        pcreator=split_line[7].strip('\r').strip('"'),
                        original=line
                    )
                except IndexError:
                    pass
                else:
                    self.iocs.append(ioc)