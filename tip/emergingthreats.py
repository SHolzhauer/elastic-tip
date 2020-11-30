from ioc import Intel
import requests
from time import time


class ETFireWallBlockIps:

    def __init__(self):
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"

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
            if line[:1] is "#" or len(line) < 2:
                pass
            else:
                try:
                    if "/" in line:
                        type = "ip_range"
                    else:
                        type = "ip_address"

                    intel = Intel(
                        original=line,
                        event_type="indicator",
                        event_reference=self._feed_url,
                        event_module="EmergingThreats",
                        event_dataset="fwrules/emerging-Block-IPs",
                        threat_first_seen=None,
                        threat_last_seen=None,
                        threat_type=type
                    )
                    intel.intel["threat"]["ioc"]["ip"] = line
                except Exception:
                    pass
                else:
                    intel.add_docid()
                    self.intel.append(intel)
