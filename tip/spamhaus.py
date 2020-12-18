from ioc import Intel
import requests
from time import time


class SpamhausDrop:

    def __init__(self):
        self._raw_threat_intel = None
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://www.spamhaus.org/drop/drop.txt"

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
            if line[:1] is ";":
                pass
            else:
                split_line = line.split(';')
                # Add as source ip
                try:
                    intel = Intel(
                        original=line,
                        event_type="indicator",
                        event_reference=self._feed_url,
                        event_provider="Spamhaus",
                        event_dataset="Spamhaus.drop",
                        threat_first_seen=None,
                        threat_last_seen=None,
                        threat_type="domain",
                        threat_description=split_line[1]
                    )
                    intel.intel["threat"]["type"] = "IPV4"
                    intel.intel["source"] = {}
                    intel.intel["source"]["ip"] = split_line[0]
                except IndexError:
                    pass
                else:
                    intel.add_docid()
                    self.intel.append(intel)
                # Add as destination ip
                try:
                    intel = Intel(
                        original=line,
                        event_type="indicator",
                        event_reference=self._feed_url,
                        event_provider="Spamhaus",
                        event_dataset="Spamhaus.drop",
                        threat_first_seen=None,
                        threat_last_seen=None,
                        threat_type="domain",
                        threat_description=split_line[1]
                    )
                    intel.intel["threat"]["type"] = "IPV4"
                    intel.intel["destination"] = {}
                    intel.intel["destination"]["ip"] = split_line[0]
                except IndexError:
                    pass
                else:
                    intel.add_docid()
                    self.intel.append(intel)


class SpamhausExtendedDrop:

    def __init__(self):
        self._raw_threat_intel = None
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://www.spamhaus.org/drop/edrop.txt"

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
            if line[:1] is ";":
                pass
            else:
                split_line = line.split(';')
                # Add as source ip
                try:
                    intel = Intel(
                        original=line,
                        event_type="indicator",
                        event_reference=self._feed_url,
                        event_provider="Spamhaus",
                        event_dataset="Spamhaus.extendeddrop",
                        threat_first_seen=None,
                        threat_last_seen=None,
                        threat_type="domain",
                        threat_description=split_line[1]
                    )
                    intel.intel["threat"]["type"] = "IPV4"
                    intel.intel["source"] = {}
                    intel.intel["source"]["ip"] = split_line[0]
                except IndexError:
                    pass
                else:
                    intel.add_docid()
                    self.intel.append(intel)
                # Add as destination ip
                try:
                    intel = Intel(
                        original=line,
                        event_type="indicator",
                        event_reference=self._feed_url,
                        event_provider="Spamhaus",
                        event_dataset="Spamhaus.extendeddrop",
                        threat_first_seen=None,
                        threat_last_seen=None,
                        threat_type="domain",
                        threat_description=split_line[1]
                    )
                    intel.intel["threat"]["type"] = "IPV4"
                    intel.intel["destination"] = {}
                    intel.intel["destination"]["ip"] = split_line[0]
                except IndexError:
                    pass
                else:
                    intel.add_docid()
                    self.intel.append(intel)


class SpamhausDropIpv6:

    def __init__(self):
        self._raw_threat_intel = None
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://www.spamhaus.org/drop/dropv6.txt"

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
            if line[:1] is ";":
                pass
            else:
                split_line = line.split(';')
                # Add as source ip
                try:
                    intel = Intel(
                        original=line,
                        event_type="indicator",
                        event_reference=self._feed_url,
                        event_provider="Spamhaus",
                        event_dataset="Spamhaus.ipv6drop",
                        threat_first_seen=None,
                        threat_last_seen=None,
                        threat_type="domain",
                        threat_description=split_line[1]
                    )
                    intel.intel["threat"]["type"] = "IPV4"
                    intel.intel["source"] = {}
                    intel.intel["source"]["ip"] = split_line[0]
                except IndexError:
                    pass
                else:
                    intel.add_docid()
                    self.intel.append(intel)
                # Add as destination ip
                try:
                    intel = Intel(
                        original=line,
                        event_type="indicator",
                        event_reference=self._feed_url,
                        event_provider="Spamhaus",
                        event_dataset="Spamhaus.ipv6drop",
                        threat_first_seen=None,
                        threat_last_seen=None,
                        threat_type="domain",
                        threat_description=split_line[1]
                    )
                    intel.intel["threat"]["type"] = "IPV4"
                    intel.intel["destination"] = {}
                    intel.intel["destination"]["ip"] = split_line[0]
                except IndexError:
                    pass
                else:
                    intel.add_docid()
                    self.intel.append(intel)