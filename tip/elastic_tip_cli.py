from sys import argv
import getopt
from elastic_tip import ElasticTip


class CLI:

    def __init__(self):
        self._arguments = []
        self._cli_head = """
Elastic Threat Intelligence Platform
                   -----------------
                   community project
===================================="""
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
            pass
        else:
            self._help()

    def _run_cli(self):
        try:
            opts, args = getopt.getopt(argv[2:], "hm:e:Tu:p:i:",
                                       ["help", "modules=", "es-hosts=", "tls", "user", "passwd", "index="])
        except getopt.GetoptError as err:
            print(err)
            exit(1)
        else:
            self._tip = ElasticTip()

        for opt, arg in opts:
            if opt in ["-h", "--help"]:
                self._run_help()
            elif opt in ["-m", "--modules"]:
                for mod in arg.split(","):
                    try:
                        # Enable the module
                        self._tip.modules["{}".format(mod)]["enabled"] = True
                    except KeyError:
                        print("Module {} does not exist".format(mod))
            elif opt in ["-e", "--es-hosts"]:
                self._tip.eshosts = arg.split(",")
            elif opt in ["-u", "--user"]:
                self._tip.esuser = arg
            elif opt in ["-p", "--passwd"]:
                self._tip.espass = arg
            elif opt in ["-i", "--index"]:
                self._tip.index = arg

        self._tip.run()

    def _init_cli(self):
        pass

    def _verify_cli(self):
        pass

    def _help(self):
        print(self._cli_head)
        print("python tip/elastic_tip_cli.py [command] [options]")
        print("")
        print("Commands:")
        print("    help")
        print("    run")
        print("    init")
        print("    verify")

    def _run_help(self):
        print(self._cli_head)
        print("python tip/elastic_tip_cli.py run [options]")
        print("")
        print("Options")
        print("    -h, --help              Print help output")
        print("    -e, --es-hosts          Comma seperated list of Elasticseerch hosts to use")
        print("    -u, --user              Username to use for Authentication to ES")
        print("    -p, --passwd            Password to use for Authentication to ES")
        print("    -m, --modules           Modules to enable:")
        tip = ElasticTip()
        for mod in tip.modules:
            print("                                {}".format(mod))
        print("    -T, --tls               Disable Certificate validation when connecting to Elasticsearch")


tip_cli = CLI()
tip_cli.cli()