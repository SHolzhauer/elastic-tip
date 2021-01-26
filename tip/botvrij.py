from ioc import Intel
import requests
import json
from time import time
from os import environ


class BotvrijFileNames:

    def __init__(self):
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://botvrij.eu/data/ioclist.filename.raw"
        self.key = None
        self._raw_threat_intel = ""

    def run(self):
        self._download()
        self._parse()

    def _download(self):
        self._retrieved = time()

        response = requests.get(
            url=self._feed_url
        )
        if response.status_code is 200:
            self._raw_threat_intel = response.text

    def _parse(self):
        for line in self._raw_threat_intel.split("\n"):
            # Add as source ip
            try:
                intel = Intel(
                    original=line,
                    event_type="indicator",
                    event_reference=self._feed_url,
                    event_provider="botvrij",
                    event_dataset="botvrij.filenames",
                    threat_first_seen=None,
                    threat_last_seen=None,
                    threat_type="file"
                )
                intel.add_file(name=line)
            except Exception:
                pass
            else:
                intel.add_docid()
                self.intel.append(intel)


class BotvrijDomains:

    def __init__(self):
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://botvrij.eu/data/ioclist.domain.raw"
        self.key = None
        self._raw_threat_intel = ""

    def run(self):
        self._download()
        self._parse()

    def _download(self):
        self._retrieved = time()

        response = requests.get(
            url=self._feed_url
        )
        if response.status_code is 200:
            self._raw_threat_intel = response.text

    def _parse(self):
        for line in self._raw_threat_intel.split("\n"):
            # Add as source ip
            try:
                intel = Intel(
                    original=line,
                    event_type="indicator",
                    event_reference=self._feed_url,
                    event_provider="botvrij",
                    event_dataset="botvrij.domains",
                    threat_first_seen=None,
                    threat_last_seen=None,
                    threat_type="url"
                )
                intel.add_url(domain=line, top_level_domain=line.split(".")[1])
            except Exception:
                pass
            else:
                intel.add_docid()
                self.intel.append(intel)


class BotvrijDstIP:

    def __init__(self):
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://botvrij.eu/data/ioclist.ip-dst.raw"
        self.key = None
        self._raw_threat_intel = ""

    def run(self):
        self._download()
        self._parse()

    def _download(self):
        self._retrieved = time()

        response = requests.get(
            url=self._feed_url
        )
        if response.status_code is 200:
            self._raw_threat_intel = response.text

    def _parse(self):
        for line in self._raw_threat_intel.split("\n"):
            # Add as source ip
            try:
                intel = Intel(
                    original=line,
                    event_type="indicator",
                    event_reference=self._feed_url,
                    event_provider="botvrij",
                    event_dataset="botvrij.ip-dst",
                    threat_first_seen=None,
                    threat_last_seen=None,
                    threat_type="IPV4"
                )
                intel.add_ip(ip=line)
            except Exception:
                pass
            else:
                intel.add_docid()
                self.intel.append(intel)


class BotvrijUrl:

    def __init__(self):
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://botvrij.eu/data/ioclist.url.raw"
        self.key = None
        self._raw_threat_intel = ""

    def run(self):
        self._download()
        self._parse()

    def _download(self):
        self._retrieved = time()

        response = requests.get(
            url=self._feed_url
        )
        if response.status_code is 200:
            self._raw_threat_intel = response.text

    def _parse(self):
        for line in self._raw_threat_intel.split("\n"):
            # Add as source ip
            try:
                intel = Intel(
                    original=line,
                    event_type="indicator",
                    event_reference=self._feed_url,
                    event_provider="botvrij",
                    event_dataset="botvrij.url",
                    threat_first_seen=None,
                    threat_last_seen=None,
                    threat_type="url"
                )
                intel.add_url(original=line)
            except Exception:
                pass
            else:
                intel.add_docid()
                self.intel.append(intel)
