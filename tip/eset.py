from os import walk
from shutil import rmtree
from ioc import Intel
from time import time
from git import Git


class EsetMalwareIOC:

    def __init__(self):
        self.intel = []
        self._retrieved = None
        self._feed_url = "https://github.com/eset/malware-ioc.git"

    def run(self):
        self._download()
        try:
            self._parse()
        except Exception as err:
            print("Failed to parse ESET IOCS: {}".format(err))
        finally:
            self._cleanup()
        print(len(self.intel))

    def _download(self):
        self._retrieved = time()
        Git("tip/githubclones/eset").clone(self._feed_url)

    def _parse(self):
        for root, dirs, files in walk("tip/githubclones/eset/malware-ioc"):
            for file in files:
                if ".git" in root:
                    continue
                elif "README" in file:
                    continue
                elif "samples" in file:
                    lines = ""
                    with open("{}/{}".format(root, file), "r") as iocfile:
                        lines = iocfile.read().split("\n")

                    for line in lines:
                        try:
                            intel = Intel(
                                original=line,
                                event_type="indicator",
                                event_reference=self._feed_url,
                                event_provider="Eset",
                                event_dataset="malware-ioc",
                                threat_first_seen=None,
                                threat_last_seen=None,
                                threat_type="file_hash"
                            )
                            if file == "samples.sha1":
                                intel.add_file(sha1=line)
                            elif file == "samples.sha256":
                                intel.add_file(sha256=line)
                            elif file == "samples.md5":
                                intel.add_file(md5=line)
                        except Exception as err:
                            print(err)
                        else:
                            intel.add_docid()
                            self.intel.append(intel)

    def _cleanup(self):
        rmtree("tip/githubclones/eset/malware-ioc")