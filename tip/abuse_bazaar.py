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
                pass
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


class MalwareBazaar:

    def __init__(self):
        self._raw_threat_intel = None
        self.iocs = []
        self._retrieved = None
        self._feed_url = "https://bazaar.abuse.ch/export/csv/recent/"

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
                pass
            else:
                split_line = line.split('", "')
                # Add SHA256 hashes
                try:
                    ioc = IOC(
                        ref=[self._feed_url],
                        value=split_line[1],
                        type="hash",
                        pname="MalwareBazaar",
                        pcreator=split_line[4],
                        original=line
                    )
                except IndexError as err:
                    pass
                else:
                    self.iocs.append(ioc)

                # Add MD5 hashes
                try:
                    ioc = IOC(
                        ref=[self._feed_url],
                        value=split_line[2],
                        type="hash",
                        pname="MalwareBazaar",
                        pcreator=split_line[4],
                        original=line
                    )
                except IndexError as err:
                    pass
                else:
                    self.iocs.append(ioc)

                # Add SHA1 hashes
                try:
                    ioc = IOC(
                        ref=[self._feed_url],
                        value=split_line[3],
                        type="hash",
                        pname="MalwareBazaar",
                        pcreator=split_line[4],
                        original=line
                    )
                except IndexError as err:
                    pass
                else:
                    self.iocs.append(ioc)


class FeodoTracker:

    def __init__(self):
        self._raw_threat_intel = None
        self.iocs = []
        self._retrieved = None
        self._feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

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
                pass
            else:
                split_line = line.split(",")
                try:
                    ioc = IOC(
                        ref=[self._feed_url],
                        value=split_line[1],
                        type="ip",
                        pname="FeodoTracker",
                        original=line
                    )
                except IndexError as err:
                    pass
                else:
                    self.iocs.append(ioc)


class SSLBlacklist:

    def __init__(self):
        self._raw_threat_intel = None
        self.iocs = []
        self._retrieved = None
        self._feed_url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"

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
                pass
            else:
                split_line = line.split(",")
                try:
                    ioc = IOC(
                        ref=[self._feed_url],
                        value=split_line[1],
                        type="hash",
                        pname="SSLBlacklist",
                        original=line
                    )
                except IndexError as err:
                    pass
                else:
                    self.iocs.append(ioc)