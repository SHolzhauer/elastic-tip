from datetime import datetime
import json
import re
import hashlib


class IOC:

    def __init__(self, ref=[], value="", type="", pname="", pcreator=None, pref=None, original=None):
        self.id = None
        self.ioc = {
          "reference": ref,
          "value": value,
          "type": type,
          "provider": {
            "name": pname
          }
        }
        if pcreator:
            self.ioc["provider"]["creator"] = pcreator
        if original:
            self.ioc["original"] = original
        if pref:
            self.ioc["provider"]["reference"] = pref
        self.threat = None
        self.vulnerability = None
        self.rule = None
        self._validate()
        self.add_docid()

    def _validate(self):
        """Validate the ioc holds to the schema"""

        # reference should be an empty array or an array of URL's
        urlmatch = 'https?:\/\/'
        if len(self.ioc["reference"]) > 0:
            for x in self.ioc["reference"]:
                if re.search(urlmatch, x):
                    continue
                else:
                    raise SchemaException("The IOC reference field is not a URL: {}".format(x))

        # Validate the type is one of the accepted values
        type_accepted = ["hash", "domain", "ip", "string", "unknown"]
        if self.ioc["type"] not in type_accepted:
            raise SchemaException("The IOC type field is not one of {}".format(type_accepted))

    def add_docid(self):
        self.id = hashlib.sha1(json.dumps(self.ioc).encode('utf-8')).hexdigest()


class Intel:

    def __init__(self,
                 original=None,
                 event_type=None,
                 event_reference=None,
                 event_module=None,
                 event_dataset=None,
                 threat_first_seen=datetime.now().strftime("%m-%d-%Y %H:%M:%S"),
                 threat_last_seen=datetime.now().strftime("%m-%d-%Y %H:%M:%S"),
                 threat_last_update=None,
                 threat_type=None,
                 threat_description=None):
        """

        :param original: original intel in its original format
        :param event_type: Type of event (indicator)
        :param event_reference: url which provides context
        :param event_module: event.module field
        :param event_dataset: event.dataset field
        :param threat_first_seen: date at which the threat was first seen or added
        :param threat_last_seen: date at which the threat was last seen to be active
        :param threat_last_update: date at which the intell has last been updated
        :param threat_type: threat.type field
        :param threat_description: description field to provide context on the intel
        """
        self.id = None
        self.intel = {
            "event": {
                "kind": "enrichment",
                "category": "threat",
                "type": event_type,
                "reference": event_reference,
                "module": event_module,
                "dataset": event_dataset,
                "severity": 0,
                "risk_score": 0,
                "original": original
            },
            "threat": {
                "ioc": {
                    "time_first_seen": threat_first_seen,
                    "time_last_seen": threat_last_seen,
                    "sightings": 0,
                    "description": threat_description,
                    "classification": threat_type,
                },
                "tactic": {},
                "technique": {}

            }
        }

    def add_mitre(self, tactic=None, technique=None):
        """

        :param tactic: Tactic ID e.g TA0002
        :param technique: Technique ID e.g T1059
        :return:
        """

        if tactic or technique:
            self.intel["threat"]["framework"] = "MITRE ATT&CK"

        if tactic:
            self.intel["threat"]["tactic"]["id"] = tactic

        if technique:
            self.intel["threat"]["technique"]["id"] = tactic

    def _add_docid(self):
        self.id = hashlib.sha1(json.dumps(self.intel).encode('utf-8')).hexdigest()
        self.intel["event"]["hash"] = self.id


class SchemaException(Exception):
    pass
