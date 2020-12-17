from ioc import Intel
import requests
import json
from time import time
from os import environ


class AbuseIPDB:

    def __init__(self):
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://api.abuseipdb.com/api/v2/blacklist"
        self.confidenceminimum = '90'
        self.key = None
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
            try:
                intel = Intel(
                    original=json.dumps(obj),
                    event_type="indicator",
                    event_reference=self._feed_url,
                    event_module="AbuseIPdb",
                    event_dataset="blacklist",
                    threat_first_seen=None,
                    threat_last_seen=obj["lastReportedAt"],
                    threat_type="ip_address"
                )
                intel.intel["threat"]["type"] = "IPV4"
                intel.intel["source"]["ip"] = obj["ipAddress"]
                intel.intel["destination"]["ip"] = obj["ipAddress"]
            except Exception:
                pass
            else:
                intel.add_docid()
                self.intel.append(intel)
