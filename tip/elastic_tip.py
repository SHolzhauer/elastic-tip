import json
import re
from abuse_bazaar import URLhaus
from elasticsearch import Elasticsearch


class ElasticTip:

    def __init__(self):
        self.index = "elastic-tip"
        self.eshosts = []
        self.esuser = None
        self.espass = None
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
                self._ingest(mod.iocs, module)

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

    def _ingest(self, iocs, mod=""):
        """Ingest IOC's into Elasticsearch"""
        es = Elasticsearch(self.eshosts)
        tens_of_thousands = "(^[1-9]*0{4,}$|^[0-9]{2,}0{3,}$)"

        print("Ingesting {} iocs from {} into {}".format(len(iocs), mod, self.eshosts))
        bulk_body = ""
        for ioc in iocs:
            bulk_body += "{ \"index\" : { \"_index\" : \"elastic-tip\", \"_id\" : \"%s\" } }\n" % ioc.ioc["_doc"]
            bulk_body += "{}\n".format(json.dumps(ioc.ioc))

            #if iocs.index(ioc) > 2:
            if re.match(tens_of_thousands, str(iocs.index(ioc))):
                res = es.bulk(body=bulk_body)
                bulk_body = ""




