from ioc import IOC, Intel
import requests
import hashlib
from time import time


class URLhaus:

    def __init__(self):
        self._raw_threat_intel = None
        self.intel = []
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
                    intel = Intel(
                        original=line,
                        event_type="indicator",
                        event_reference=self._feed_url,
                        event_module="Abuse.ch",
                        event_dataset="URLhaus",
                        threat_first_seen=line[1],
                        threat_last_seen=None,
                        threat_type="domain"
                    )
                    intel.intel["threat"]["url"] = {}
                    intel.intel["threat"]["url"]["full"] = split_line[2]
                except IndexError:
                    pass
                else:
                    self.intel.append(intel)


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
        self.intel = []
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
                    intel = Intel(
                        original=line,
                        event_type="indicator",
                        event_reference=self._feed_url,
                        event_module="Abuse.ch",
                        event_dataset="FeodoTracker",
                        threat_first_seen=line[0],
                        threat_last_seen=line[3],
                        threat_type="ip_address"
                    )
                    intel.intel["threat"]["ip"] = line[1]
                except IndexError as err:
                    pass
                else:
                    self.intel.append(intel)


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