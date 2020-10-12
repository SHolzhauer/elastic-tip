import json
import re
from abuse_bazaar import URLhaus, MalwareBazaar, FeodoTracker, SSLBlacklist
from elasticsearch import Elasticsearch


class ElasticTip:

    def __init__(self):
        self.index = "elastic-tip"
        self.eshosts = []
        self.esuser = None
        self.espass = None
        self._es = None
        self.modules = {
            "URLhaus": {
                "enabled": False,
                "class": URLhaus()
            },
            "MalwareBazaar": {
                "enabled": False,
                "class": MalwareBazaar()
            },
            "FeodoTracker": {
                "enabled": False,
                "class": FeodoTracker()
            },
            "SSLBlacklist": {
                "enable": False,
                "class": SSLBlacklist()
            }
        }

    def run(self):
        if not self._es:
            self._es = Elasticsearch(hosts=self.eshosts)
        self.verify_tip()
        print("Running TIP")
        for module in self.modules:
            if self.modules[module]["enabled"]:
                mod = self.modules[module]["class"]
                mod.run()
                self._ingest(mod.iocs, module)
        self._es.indices.refresh(index=self.index)

    def init_tip(self):
        """Initilize the TIP"""
        print("Initilizing TIP")
        for module in self.modules:
            if self.modules[module]["enabled"]:
                mod = self.modules[module]["class"]
                mod.run()

    def verify_tip(self):
        """Verify the config of the TIP"""
        if not self._es:
            self._es = Elasticsearch(hosts=self.eshosts)
        print("Verifying TIP")
        # Get elasticsearch index settings from files
        index_settings = None
        index_mapping = None
        with open("tip/elasticsearch/index_settings.json", "r") as file:
            index_settings = json.loads(file.read())
        with open("tip/elasticsearch/index_mapping.json", "r") as file:
            index_mapping = json.loads(file.read())
        # Verify the index exists
        if self._es.indices.exists(index=self.index):
            print("Index {} exists".format(self.index))
        else:
            print("Index {} does not exists, creating...".format(self.index))
            try:
                self._es.indices.create(
                    index=self.index,
                    body={
                        "settings": index_settings,
                        "mappings": index_mapping
                    }
                )
            except Exception as err:
                print(err)
                exit()

    def _ingest(self, iocs, mod=""):
        """Ingest IOC's into Elasticsearch"""
        tens_of_thousands = "(^[1-9]*0{4,}$|^[0-9]{2,}0{3,}$)"

        print("Ingesting {} iocs from {} into {}".format(len(iocs), mod, self.eshosts))
        bulk_body = ""
        for ioc in iocs:
            bulk_body += "{ \"update\" : { \"_index\" : \"elastic-tip\", \"_id\" : \"%s\" } }\n" % ioc.id
            bulk_body += '{ "doc_as_upsert": true, "doc": %s }\n' % json.dumps(ioc.ioc)

            # Do a bulk update for every 10'th of thousands
            if re.match(tens_of_thousands, str(iocs.index(ioc))):
                res = self._es.bulk(body=bulk_body)
                bulk_body = ""
        # Ingest the last batch or if there are less as 10000 documents
        res = self._es.bulk(body=bulk_body)
