from ioc import Intel
import requests
import json
from time import time
from os import environ


class AbuseIPDB:

    def __init__(self, conf=None):
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://api.abuseipdb.com/api/v2/blacklist"
        self._conf = conf
        self.confidenceminimum = self._conf["AbuseIPdb"].getint("confidenceminimum")
        self.key = self._conf["AbuseIPdb"].getint("apikey")
        self._raw_threat_intel = {
            "data": []
        }

    def run(self):
        if not self.key:
            try:
                self.key = environ["ABUSE_IP_KEY"]
            except KeyError:
                self.key = input("AbuseIP DB API Key: ")
        self._download()
        self._parse()

    def _download(self):
        self._retrieved = time()

        querystring = {
            "confidenceMinimum": self.confidenceminimum
        }
        headers = {
            'Accept': 'application/json',
            'Key': self.key
        }
        response = requests.get(
            url=self._feed_url,
            headers=headers,
            params=querystring
        )
        if response.status_code is 200:
            self._raw_threat_intel = json.loads(response.text)
        elif response.status_code is 429:
            print("Rate limit exceeded for abuseipdb")

    def _parse(self):
        for obj in self._raw_threat_intel["data"]:
            # Add as source ip
            try:
                intel = Intel(
                    original=json.dumps(obj),
                    event_type="indicator",
                    event_reference=self._feed_url,
                    event_provider="AbuseIPdb",
                    event_dataset="blacklist",
                    threat_first_seen=None,
                    threat_last_seen=obj["lastReportedAt"],
                    threat_type="ip_address"
                )
                intel.add_ip(ip=obj["ipAddress"])
            except Exception:
                pass
            else:
                intel.add_docid()
                self.intel.append(intel)
