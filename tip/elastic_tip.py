from abuse_bazaar import URLhaus
from elasticsearch import Elasticsearch


class ElasticTip:

    def __init__(self):
        self.index = "elastic-tip"
        self.eshost = []
        self.modules = {
            "URLHaus": {
                "enabled": False,
                "class": URLhaus()
            }
        }

    def run(self):
        print("Running TIP")
        for module in self.modules:
            if self.modules[module]["enabled"]:
                mod = self.modules[module]["class"]
                mod.run()
                self._ingest(mod.iocs)

    def init_tip(self):
        """Initilize the TIP"""
        print("Initilizing TIP")
        for module in self.modules:
            if self.modules[module]["enabled"]:
                mod = self.modules[module]["class"]
                mod.run()

    def verify_tip(self):
        """Verify the config of the TIP"""
        print("Verifying TIP")

    def _ingest(self, iocs):
        """Ingest IOC's into Elasticsearch"""
        es = Elasticsearch(self.eshosts)

        for ioc in iocs:
            res = es.index(
                index=self.index,
                body=ioc,
                id=ioc["_doc"]
            )

