import hashlib
import json
import re
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import streaming_bulk
import tqdm

from abuse_bazaar import URLhaus, MalwareBazaar, FeodoTracker, SSLBlacklist
from emergingthreats import ETFireWallBlockIps
from eset import EsetMalwareIOC
from abuseipdb import AbuseIPDB
from spamhaus import SpamhausDrop, SpamhausExtendedDrop, SpamhausDropIpv6
from botvrij import BotvrijFileNames, BotvrijDomains, BotvrijDstIP, BotvrijUrl


class ElasticTip:

    def __init__(self):
        self.index = "elastic-tip"
        self.eshosts = []
        self.esport = 9200
        self.esuser = None
        self.espass = None
        self.setup_index = True
        self.tls = {
            "use": True,
            "cacert": None,
            "verify": True
        }
        self._es = None
        self._total_count = 0
        self._ids = []
        self.modules = {
            "URLhaus": {
                "enabled": False,
                "class": URLhaus(),
                "ref": "https://urlhaus.abuse.ch/",
                "note": None
            },
            "MalwareBazaar": {
                "enabled": False,
                "class": MalwareBazaar(),
                "ref": "https://bazaar.abuse.ch/",
                "note": None
            },
            "FeodoTracker": {
                "enabled": False,
                "class": FeodoTracker(),
                "ref": "https://feodotracker.abuse.ch/",
                "note": None
            },
            "SSLBlacklist": {
                "enabled": False,
                "class": SSLBlacklist(),
                "ref": "https://sslbl.abuse.ch/",
                "note": None
            },
            "EmergingThreats-Blocklist": {
                "enabled": False,
                "class": ETFireWallBlockIps(),
                "ref": "https://rules.emergingthreats.net/",
                "note": None
            },
            "ESET-MalwareIOC": {
                "enabled": False,
                "class": EsetMalwareIOC(),
                "ref": "https://github.com/eset/malware-ioc",
                "note": None
            },
            "AbuseIPdb": {
                "enabled": False,
                "class": AbuseIPDB(),
                "ref": "https://www.abuseipdb.com/",
                "note": "AbuseIPdb requires an API key to work, this can be set through the 'ABUSE_IP_KEY' environment variable or will be requested upon runtime"
            },
            "Spamhaus-Drop": {
                "enabled": False,
                "class": SpamhausDrop(),
                "ref": "https://www.spamhaus.org/drop/",
                "note": None
            },
            "Spamhaus-ExtendedDrop": {
                "enabled": False,
                "class": SpamhausExtendedDrop(),
                "ref": "https://www.spamhaus.org/drop/",
                "note": None
            },
            "Spamhaus-IPv6Drop": {
                "enabled": False,
                "class": SpamhausDropIpv6(),
                "ref": "https://www.spamhaus.org/drop/",
                "note": None
            },
            "Botvrij-filenames": {
                "enabled": False,
                "class": BotvrijFileNames(),
                "ref": "https://botvrij.eu/data/ioclist.filename.raw",
                "note": None
            },
            "Botvrij-domains": {
                "enabled": False,
                "class": BotvrijDomains(),
                "ref": "https://botvrij.eu/data/ioclist.domain.raw",
                "note": None
            },
            "Botvrij-destinations": {
                "enabled": False,
                "class": BotvrijDstIP(),
                "ref": "https://botvrij.eu/data/ioclist.ip-dst.raw",
                "note": None
            },
            "Botvrij-urls": {
                "enabled": False,
                "class": BotvrijUrl(),
                "ref": "https://botvrij.eu/data/ioclist.url.raw",
                "note": None
            }
        }
        self._total_ingested = 0

    def run(self):
        self._build_es_conn()
        self.verify_tip()
        print("Running TIP")
        for module in self.modules:
            if self.modules[module]["enabled"]:
                mod = self.modules[module]["class"]
                mod.run()
                try:
                    self._ingest(mod.iocs, module)
                except AttributeError:
                    if len(mod.intel) > 0:
                        self._ingest(mod.intel, module, True)
        self._es.indices.refresh(index=self.index)
        print("=======================================")
        print("Ingested a total of {} IOC's".format(self._total_ingested))
        print("=======================================")

    def init_tip(self):
        """Initilize the TIP"""
        print("Initilizing TIP")
        for module in self.modules:
            if self.modules[module]["enabled"]:
                mod = self.modules[module]["class"]
                mod.run()

    def verify_tip(self):
        """Verify the config of the TIP"""
        self._build_es_conn()
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
            if self.setup_index:
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
            else:
                pass

    def _build_es_conn(self):
        if not self._es:
            eshosts = []
            for hoststring in self.eshosts:

                # Determine host and port
                host, port = self._parse_hosts(hoststring)

                host_block = {
                    'host': host,
                    'port': port
                }
                if not self.tls["use"]:
                    host_block["use_ssl"] = False
                else:
                    host_block["use_ssl"] = True

                if self.tls["cacert"]:
                    host_block["ca_certs"] = self.tls["cacert"]

                if not self.tls["verify"]:
                    host_block["verify_certs"] = False
                    host_block["ssl_show_warn"] = False
                eshosts.append(host_block)
            self.eshosts = eshosts
            if self.esuser:
                self._es = Elasticsearch(hosts=self.eshosts, http_auth=(self.esuser, self.espass))
            else:
                self._es = Elasticsearch(hosts=self.eshosts)
        print("Connection: {}".format(self._es))

    def _parse_hosts(self, hoststring):
        """Parse a host string to determine host and port"""
        host = port = None
        if ":" in hoststring:
            arr = hoststring.split(":")
            if len(arr) > 2:
                raise IndexError("es hosts is malformed")
            host = arr[0]
            port = int(float(arr[1]))
        else:
            host = hoststring
            port = self.esport

        return host, port

    def _ingest(self, iocs, mod="", intel=False):
        """Ingest IOC's into Elasticsearch"""
        tens_of_thousands = "(^[1-9]*0{4,}$|^[0-9]{2,}0{3,}$)"

        print("Ingesting {} iocs from {}".format(len(iocs), mod, self.eshosts))
        self._total_count += len(iocs)

        progress = tqdm.tqdm(unit="docs", total=len(iocs))
        successes = 0
        try:
            for ok, action in streaming_bulk(
                    client=self._es,
                    index=self.index,
                    actions=self._generate_es_actions(iocs),
            ):
                if ok:
                    progress.update(1)
                    successes += ok
                else:
                    print(ok)
                    print(action)
        except Exception as err:
            print(err)
        print("Indexed %d/%d documents" % (successes, len(iocs)))
        print("Duplicates are not counted!")

    def _generate_es_actions(self, documents):
        ids = []
        for ioc in documents:
            if not ioc.id in ids:
                ids.append(ioc.id)
                self._total_ingested += 1
                yield {
                    "_index": self.index,
                    "_id": ioc.id,
                    "doc": ioc.intel,
                    "_op_type": "index"
                }
