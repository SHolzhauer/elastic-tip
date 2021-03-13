from sys import argv
import getopt
from os import path
from elastic_tip import ElasticTip
import configparser


class CLI:

    def __init__(self):
        self._arguments = []
        self._cli_head = """
Elastic Threat Intelligence Platform
                            ----------------------
                                 community project
==================================================
"""
        self._cli_footer = """
==================================================
Author   Stijn Holzhauer
Website  https://github.com/SHolzhauer/elastic-tip"""
        self._tip = None
        self._mod = None

    def cli(self):
        if argv[1] == "help":
            self._help()
        elif argv[1] == "run":
            self._run_cli()
        elif argv[1] == "init":
            pass
        elif argv[1] == "verify":
            self._verify_cli()
        else:
            self._help()

    def _run_cli(self):
        if len(argv) < 3:
            self._run_help()
            exit()

        try:
            opts, args = getopt.getopt(argv[2:], "hm:e:Tu:p:P:i:c:C:",
                                       ["help", "modules=", "modules-list", "es-hosts=", "es-port=", "tls", "user=", "passwd=", "index=", "ca-cert=", "no-verify", "config-file="])
        except getopt.GetoptError as err:
            print(err)
            exit(1)
        else:
            self._tip = ElasticTip()

        # If a conf file is provided load it first
        for opt, arg in opts:
            if opt in ["-C", "--config-file"]:
                self._tip.load_conf_file(arg)

        # Either create a new conf or use the one from the file
        if not self._tip.conf:
            config = configparser.ConfigParser()
            config["Elasticsearch"] = {
                    "tls_verify": "True",
                    "use_tls": "True",
                    "setup_index": "True"
                }
            config["URLhaus"] = {"enabled": "False"}
            config["MalwareBazaar"] = {"enabled": "False"}
            config["FeodoTracker"] = {"enabled": "False"}
            config["SSLBlacklist"] = {"enabled": "False"}
            config["EmergingThreats-Blocklist"] = {"enabled": "False"}
            config["ESET-MalwareIOC"] = {"enabled": "False"}
            config["AbuseIPdb"] = {
                    "enabled": "False",
                    "apikey": "",
                    "confidenceminimum": 90
                }
            config["Spamhaus-Drop"] = {"enabled": "False"}
            config["Spamhaus-ExtendedDrop"] = {"enabled": "False"}
            config["Spamhaus-IPv6Drop"] = {"enabled": "False"}
            config["Botvrij-filenames"] = {"enabled": "False"}
            config["Botvrij-domains"] = {"enabled": "False"}
            config["Botvrij-destinations"] = {"enabled": "False"}
            config["Botvrij-urls"] = {"enabled": "False"}
        else:
            # Load the existing one, provided commandline args will overwrite the file
            config = self._tip.conf

        for opt, arg in opts:
            if opt in ["-h", "--help"]:
                self._run_help()
                exit()
            elif opt in ["--modules-list"]:
                print(self._cli_head)
                print("IOC Modules:")
                for mod in self._tip.modules:
                    spaces = " "
                    for i in range(0, (30 - len(mod))):
                        spaces += " "
                    print("  {}{}{}".format(mod, spaces, self._tip.modules[mod]["ref"]))
                    if self._tip.modules[mod]["note"]:
                        print("          {}".format(self._tip.modules[mod]["note"]))
                exit()
                print(self._cli_footer)
            elif opt in ["-m", "--modules"]:
                # Build a config
                if "*" in arg:
                    for section in config.sections():
                        if "enabled" in section:
                            config[section]["enabled"] = "True"
                else:
                    for mod in arg.split(","):
                        try:
                            # Enable the module
                            config[mod]["enabled"] = "True"
                        except KeyError:
                            print("Module {} does not exist".format(mod))
            elif opt in ["-e", "--es-hosts"]:
                config["Elasticsearch"]["hosts"] = arg
            elif opt in ["-P", "--es-port"]:
                config["Elasticsearch"]["port"] = arg
            elif opt in ["-u", "--user"]:
                config["Elasticsearch"]["username"] = arg
            elif opt in ["-p", "--passwd"]:
                config["Elasticsearch"]["password"] = arg
            elif opt in ["-i", "--index"]:
                config["Elasticsearch"]["index"] = arg
            elif opt in ["-T", "--tls"]:
                config["Elasticsearch"]["use_tls"] = arg
            elif opt in ["-c", "--ca-cert"]:
                # make sure the file exists
                if not path.exists(arg):
                    raise FileNotFoundError("The provided cacert file cannot be found")
                else:
                    config["Elasticsearch"]["cacert"] = arg
            elif opt in ["--no-verify"]:
                config["Elasticsearch"]["tls_verify"] = arg
            elif opt in ["--no-setup"]:
                config["Elasticsearch"]["setup_index"] = arg

        self._tip.run()

    def _init_cli(self):
        pass

    def _verify_cli(self):
        if len(argv) < 3:
            self._verify_help()
            exit()

        try:
            opts, args = getopt.getopt(argv[2:], "he:Tu:P:p:i:c:",
                                       ["help", "es-hosts=", "es-port=" "tls", "user=", "passwd=", "index=", "ca-cert=", "no-verify"])
        except getopt.GetoptError as err:
            print(err)
            exit(1)
        else:
            self._tip = ElasticTip()
            for opt, arg in opts:
                if opt in ["-h", "--help"]:
                    self._verify_help()
                    exit()
                elif opt in ["-e", "--es-hosts"]:
                    hosts = arg.split(",")
                    for host in hosts:
                        if "://" in host:
                            parsedhost = host.split("://")[1]
                        else:
                            parsedhost = host
                        self._tip.eshosts.append(parsedhost)
                elif opt in ["-P", "--es-port"]:
                    self._tip.esport = int(float(arg))
                elif opt in ["-u", "--user"]:
                    self._tip.esuser = arg
                elif opt in ["-p", "--passwd"]:
                    self._tip.espass = arg
                elif opt in ["-i", "--index"]:
                    self._tip.index = arg
                elif opt in ["-T", "--tls"]:
                    self._tip.tls["use"] = False
                elif opt in ["-c", "--ca-cert"]:
                    self._tip.tls["cacert"] = arg
                elif opt in ["--no-verify"]:
                    self._tip.tls["verify"] = False

            self._tip.verify_tip()

    def _help(self):
        print(self._cli_head)
        print("python tip/elastic_tip_cli.py [command] [options]")
        print("")
        print("Commands:")
        print("    help           Print this help output")
        print("    run            Run the platform and ingest IOC's into ElasticSearch")
        print("    init           Initilize for the first time and load the full IOC lists into ElasticSearch")
        print("    verify         Verify the ElasticSearch index and connection")
        print(self._cli_footer)

    def _run_help(self):
        print(self._cli_head)
        print("python tip/elastic_tip_cli.py run [options]")
        print("")
        print("    The run command is used to run the Elastic Threat Intelligence Platform and load")
        print("    the Threat Intelligence, in the form of Indicators Of Compromise (IOC) into")
        print("    your ElasticSearch cluster to be used by the build in Detection-Engine")
        print("")
        print("Options")
        print("    -h, --help                Print help output")
        print("    -e, --es-hosts <value>    Comma seperated list of Elasticsearch hosts to use")
        print("                              E.G:"
              "                                  localhost,127.0.0.2"
              "                                  my-es.com:9300")
        print("    -P, --es-port <value>     Port to use when connecting to Elasticsearch hosts")
        print("    -i, --index <value>       The index to ingest data into")
        print("    -u, --user <value>        Username to use for Authentication to ES")
        print("    -p, --passwd <value>      Password to use for Authentication to ES")
        print("    --modules-list            List module names and the reference link")
        print("    -m, --modules <values>    Modules to enable (* for all):")
        tip = ElasticTip()
        for mod in tip.modules:
            print("                                  {}".format(mod))
        print("    -T, --tls                 Do not use TLS/SSL when connecting to Elasticsearch")
        print("    -c, --ca-cert <value>     Use the cert specified by path")
        print("    --no-verify               Don't verify the TLS/SSL certificate")
        print("    --no-setup                Do not add the index mapping and settings to the given index. Only applicable if the index doesn't exist yet.")
        print(self._cli_footer)

    def _verify_help(self):
        print(self._cli_head)
        print("python tip/elastic_tip_cli.py verify [options]")
        print("")
        print("Options")
        print("    -h, --help                Print help output")
        print("    -e, --es-hosts <value>    Comma seperated list of Elasticsearch hosts to use")
        print("    -i, --index <value>       The index to ingest data into")
        print("    -u, --user <value>        Username to use for Authentication to ES")
        print("    -p, --passwd <value>      Password to use for Authentication to ES")
        print("    -T, --tls                 Do not use TLS/SSL when connecting to Elasticsearch")
        print("    -c, --ca-cert <value>     Use the cert specified by path")
        print("    --no-verify               Don't verify the TLS/SSL certificate")
        print(self._cli_footer)


tip_cli = CLI()
tip_cli.cli()