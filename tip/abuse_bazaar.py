import requests


class URLhaus:

    def __init__(self):
        self.index = "tip-urlhaus"
        self._raw_threat_intel = None
        self._threat_intel = []

    def run(self):
        print("HI")
        self._download()
        self._parse()

    def _download(self):
        response = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/")
        if response.status_code is 200:
            self._raw_threat_intel = response.text

    def _parse(self):
        for line in self._raw_threat_intel.split("\n"):
            if line[:1] is "#":
                print(line)
            else:
                split_line = line.split('","')
                intel = {
                    "threat": {
                        "framework"
                    }
                }