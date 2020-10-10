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
        elif argv[1] == "init":
            pass
        elif argv[1] == "verify":
            pass
        elif argv[1] == "run":
            pass

    def _run_cli(self):
        try:
            opts, args = getopt.getopt(argv[2:], "hivrm:e:T", ["help", "init", "verify", "run", "modules=", "eshosts=", "tls="])
        except getopt.GetoptError as err:
            print(err)
        for opt, arg in opts:
            if opt in ["-i", "--init"]:
                if not self._tip:
                    self._tip = ElasticTip()
                self._mod = "init"
            elif opt in ["-v", "--verify"]:
                if not self._tip:
                    self._tip = ElasticTip()
                self._mod = "verify"
            elif opt in ["-r", "--run"]:
                if not self._tip:
                    self._tip = ElasticTip()
                self._mod = "run"
            elif opt in ["-m", "--modules"]:
                if not self._tip:
                    print("make tip")
                    self._tip = ElasticTip()
                for mod in arg.split(","):
                    try:
                        # Enable the module
                        self._tip.modules["{}".format(mod)]["enabled"] = True
                    except KeyError:
                        print("Module {} does not exist".format(mod))
            elif opt in ["-S", "--tls"]:
                pass
            elif opt in ["-e", "--eshosts"]:
                if not self._tip:
                    self._tip = ElasticTip()
                for host in arg.split(","):
                    self._tip.eshosts.append(host)

        # Run tip if set
        if self._tip and self._mod is "run":
            self._tip.run()
        elif self._tip and self._mod is "init":
            self._tip.init_tip()

    def _help(self):
        print(self._cli_head)
        print("Commands:")
        print("  -h, --help")
        print("  -i, --init")
        print("  -v, --verify")
        print("  -r, --run")

tip_cli = CLI()
tip_cli.cli()