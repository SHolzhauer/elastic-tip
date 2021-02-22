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
                 event_provider=None,
                 event_dataset=None,
                 threat_first_seen=None,
                 threat_last_seen=None,
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
                "provider": event_provider,
                "dataset": event_dataset,
                "severity": 0,
                "risk_score": 0,
                "original": original
            },
            "ecs": {
              "version": "1.8.0"
            },
            "threat": {
                "indicator": {
                    "first_seen": threat_first_seen,
                    "last_seen": threat_last_seen,
                    "sightings": 0,
                    "type": [],
                    "description": threat_description,
                },
                "tactic": {},
                "technique": {}

            }
        }
        self._add_type(threat_type)

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

    def add_docid(self):
        self.id = hashlib.sha1(json.dumps(self.intel).encode('utf-8')).hexdigest()
        self.intel["event"]["hash"] = self.id

    def _add_type(self, indicator_type=None):
        if indicator_type:
            self.intel["threat"]["indicator"]["type"].append(indicator_type)

    def _build_traffic(self, object,
                       domain=None,
                       ip=None,
                       mac=None,
                       port=None,
                       registered_domain=None,
                       subdomain=None,
                       top_level_domain=None):
        """Shared function to build source & destination blocks
        :param object: The name of the field to build (source/destination)
        :param domain:
        :param ip:
        :param mac:
        :param port:
        :param registered_domain:
        :param subdomain:
        :param top_level_domain:
        :return:"""
        raise OutDatedException()
        if object not in ["source", "destination"]:
            raise KeyError("wrong object specified")
        try:
            obj = self.intel[object]
        except KeyError:
            obj = {}
        finally:
            if domain:
                obj["domain"] = domain
            if ip:
                obj["ip"] = ip
            if mac:
                obj["mac"] = mac
            if port:
                obj["port"] = port
            if registered_domain:
                obj["registered_domain"] = registered_domain
            if subdomain:
                obj["subdomain"] = subdomain
            if top_level_domain:
                obj["top_level_domain"] = top_level_domain

            self.intel[object] = obj
            self.intel["threat"]["type"] = "IPV4"

    def add_ip(self, domain=None, ip=None, mac=None, port=None, registered_domain=None, subdomain=None, top_level_domain=None):
        """
        Add network information as indicator
        :param domain: domain name
        :param ip: IPv4 or IPv6 address
        :param mac:
        :param port: Port number
        :param registered_domain:
        :param subdomain:
        :param top_level_domain:
        :return:
        """
        if domain:
            self.intel["threat"]["indicator"]["domain"] = domain
        if ip:
            self.intel["threat"]["indicator"]["ip"] = ip
        if port:
            self.intel["threat"]["indicator"]["port"] = port

    def add_malware(self, name=None, family=None, malware_type=None):
        try:
            obj = self.intel["threat"]["malware"]
        except KeyError:
            obj = {}
        finally:
            if name:
                obj["name"] = name
            if family:
                obj["family"] = family
            if malware_type:
                obj["type"] = malware_type

            # Add object to intel
            self.intel["threat"]["malware"] = obj

    def add_file(self, directory=None, drive_letter=None, extension=None, gid=None, group=None, mime_type=None,
                 mode=None, name=None, owner=None, path=None, size=None, uid=None, md5=None, sha1=None, sha256=None,
                 sha512=None):
        try:
            obj = self.intel["file"]
        except KeyError:
            obj = {}
        finally:
            if directory:
                obj["directory"] = directory
            if drive_letter:
                obj["drive_letter"] = drive_letter
            if extension:
                obj["extension"] = extension
            if gid:
                obj["gid"] = gid
            if group:
                obj["group"] = group
            if mime_type:
                obj["mime_type"] = mime_type
            if mode:
                obj["mode"] = mode
            if name:
                obj["name"] = name
            if owner:
                obj["owner"] = owner
            if path:
                obj["path"] = path
            if size:
                obj["size"] = size
            if uid:
                obj["uid"] = uid
            if md5:
                try:
                    x = obj["hash"]
                except KeyError:
                    obj["hash"] = {}
                finally:
                    obj["hash"]["md5"] = md5
            if sha1:
                try:
                    x = obj["hash"]
                except KeyError:
                    obj["hash"] = {}
                finally:
                    obj["hash"]["sha1"] = sha1
            if sha256:
                try:
                    x = obj["hash"]
                except KeyError:
                    obj["hash"] = {}
                finally:
                    obj["hash"]["sha256"] = sha256
            if sha512:
                try:
                    x = obj["hash"]
                except KeyError:
                    obj["hash"] = {}
                finally:
                    obj["hash"]["sha512"] = sha512

            self.intel["file"] = obj

    def add_process(self):
        pass

    def add_x509(self, alt_names=None, iss_common=None, iss_country=None, iss_distinguished=None, iss_local=None,
                 iss_org=None, iss_org_unit=None, iss_state=None, not_after=None, not_before=None, pup_key_algo=None,
                 pup_key_curve=None, pup_key_ex=None, pup_key_size=None, serial=None, signature_algo=None,
                 subject_common=None, subject_country=None, subject_distinguished=None, subject_local=None,
                 subject_org=None, subject_org_unit=None, subject_state=None, version=None):
        try:
            obj = self.intel["x509"]
        except KeyError:
            obj = {}

        # make sure issuer object exists
        if iss_common or iss_country or iss_distinguished or iss_local or iss_org or iss_org_unit or iss_state:
            try:
                iss = obj["issuer"]
            except KeyError:
                obj["issuer"] = {}
        # make sure subject object exists
        if subject_common or subject_country or subject_distinguished or subject_local or subject_org or subject_org_unit or subject_state:
            try:
                sub = obj["subject"]
            except KeyError:
                obj["subject"] = {}

        if alt_names:
            obj["alternative_names"] = alt_names
        if iss_common:
            obj["issuer"]["common_name"] = iss_common
        if iss_country:
            obj["issuer"]["country"] = iss_country
        if iss_distinguished:
            obj["issuer"]["distinguished_name"] = iss_distinguished
        if iss_local:
            obj["issuer"]["locality"] = iss_local
        if iss_org:
            obj["issuer"]["organization"] = iss_org
        if iss_org_unit:
            obj["issuer"]["organizational_unit"] = iss_org_unit
        if iss_state:
            obj["issuer"]["state_or_province"] = iss_state
        if not_after:
            obj["not_after"] = not_after
        if not_before:
            obj["not_before"] = not_before
        if pup_key_algo:
            obj["public_key_algorithm"] = pup_key_algo
        if pup_key_curve:
            obj["public_key_curve"] = pup_key_curve
        if pup_key_ex:
            obj["public_key_exponent"] = pup_key_ex
        if pup_key_size:
            obj["public_key_size"] = pup_key_size
        if serial:
            obj["serial_number"] = serial
        if signature_algo:
            obj["signature_algorithm"] = signature_algo
        if subject_common:
            obj["subject"]["common_name"] = subject_common
        if subject_country:
            obj["subject"]["country"] = subject_country
        if subject_distinguished:
            obj["subject"]["distinguished_name"] = subject_distinguished
        if subject_local:
            obj["subject"]["locality"] = subject_local
        if subject_org:
            obj["subject"]["organization"] = subject_org
        if subject_org_unit:
            obj["subject"]["organizational_unit"] = subject_org_unit
        if subject_state:
            obj["subject"]["state_or_province"] = subject_state
        if version:
            obj["version_number"] = version

        self.intel["x509"] = obj

    def add_pe(self):
        pass

    def add_url(self, domain=None, extension=None, fragment=None, full=None, original=None, password=None, path=None,
                port=None, query=None, registered_domain=None, scheme=None, subdomain=None, top_level_domain=None,
                username=None):
        try:
            obj = self.intel["url"]
        except KeyError:
            obj = {}
        finally:
            # Do some parsing of stuff to fill in non-existing fields
            if not scheme and original and "://" in original:
                scheme = original.split("://")[0]
            elif not scheme and full and "://" in full:
                scheme = full.split("://")[0]
            if not original and full:
                original = full

            if domain:
                obj["domain"] = domain
            if extension:
                obj["extension"] = extension
            if fragment:
                obj["fragment"] = fragment
            if full:
                obj["full"] = full
            if original:
                obj["original"] = original
            if password:
                obj["password"] = password
            if path:
                obj["path"] = path
            if port:
                obj["port"] = port
            if query:
                obj["query"] = query
            if registered_domain:
                obj["registered_domain"] = registered_domain
            if scheme:
                obj["scheme"] = scheme
            if subdomain:
                obj["subdomain"] = subdomain
            if top_level_domain:
                obj["top_level_domain"] = top_level_domain
            if username:
                obj["username"] = username

        self.intel["url"] = obj

    def add_tls(self, cipher=None, c_cert=None, c_chain=None, c_md5=None, c_sha1=None, c_sha256=None, c_issuer=None,
                c_ja3=None, c_not_after=None, c_not_before=None, c_server_name=None, c_subject=None, curve=None,
                s_cert=None, s_chain=None, s_md5=None, s_sha1=None, s_sha256=None, s_issuer=None,
                s_ja3=None, s_not_after=None, s_not_before=None, s_server_name=None, s_subject=None):
        try:
            obj = self.intel["tls"]
        except KeyError:
            obj = {}

        # Make sure the required nested fields are available
        if c_cert or c_chain or c_md5 or c_sha1 or c_sha256 or c_issuer or c_ja3 or c_not_after or c_not_before or c_server_name or c_subject:
            try:
                iss = obj["client"]
            except KeyError:
                obj["client"] = {}
            if c_md5 or c_sha1 or c_sha256:
                try:
                    hash = obj["client"]["hash"]
                except KeyError:
                    obj["client"]["hash"] = {}
        if s_cert or s_chain or s_md5 or s_sha1 or s_sha256 or s_issuer or s_ja3 or s_not_after or s_not_before or s_server_name or s_subject:
            try:
                iss = obj["server"]
            except KeyError:
                obj["server"] = {}
            if s_md5 or s_sha1 or s_sha256:
                try:
                    hash = obj["server"]["hash"]
                except KeyError:
                    obj["server"]["hash"] = {}

        if cipher:
            obj[""] = cipher
        if c_cert:
            obj["client"]["certificate"] = c_cert
        if c_chain:
            obj["client"]["certificate_chain"] = c_chain
        if c_md5:
            obj["client"]["hash"]["md5"] = c_md5
        if c_sha1:
            obj["client"]["hash"]["sha1"] = c_sha1
        if c_sha256:
            obj["client"]["hash"]["sha256"] = c_sha256
        if c_issuer:
            obj["client"]["issuer"] = c_issuer
        if c_ja3:
            obj["client"]["ja3"] = c_ja3
        if c_not_after:
            obj["client"]["not_after"] = c_not_after
        if c_not_before:
            obj["client"]["not_before"] = c_not_before
        if c_server_name:
            obj["client"]["server_name"] = c_server_name
        if c_subject:
            obj["client"]["subject"] = c_subject
        if curve:
            obj[""] = curve
        if s_cert:
            obj["server"]["certificate"] = s_cert
        if s_chain:
            obj["server"]["certificate_chain"] = s_chain
        if s_md5:
            obj["server"]["hash"]["md5"] = s_md5
        if s_sha1:
            obj["server"]["hash"]["sha1"] = s_sha1
        if s_sha256:
            obj["server"]["hash"]["sha256"] = s_sha256
        if s_issuer:
            obj["server"]["issuer"] = s_issuer
        if s_ja3:
            obj["server"]["ja3s"] = s_ja3
        if s_not_after:
            obj["server"]["not_after"] = s_not_after
        if s_not_before:
            obj["server"]["not_before"] = s_not_before
        if s_server_name:
            obj["server"]["server_name"] = s_server_name
        if s_subject:
            obj["server"]["subject"] = s_subject

        self.intel["tls"] = obj


class SchemaException(Exception):
    pass


class OutDatedException(Exception):
    pass