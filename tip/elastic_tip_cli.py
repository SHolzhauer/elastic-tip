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
        try:
            opts, args = getopt.getopt(argv[1:], "hivrm:", ["help", "init", "verify", "run", "modules="])
        except getopt.GetoptError as err:
            print(err)
        for opt, arg in opts:
            if opt in ["-h", "--help"]:
                self._help()
            elif opt in ["-i", "--init"]:
                self._tip = ElasticTip()
                self._mod = "init"
            elif opt in ["-v", "--verify"]:
                self._tip = ElasticTip()
                self._mod = "verify"
            elif opt in ["-r", "--run"]:
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

        # Run tip if set
        if self._tip and self._mod is "run":
            self._tip.run()
        elif self._tip and self._mod is "init":
            self._tip.init_tip()

    def _help(self):
        print(self._cli_head)
        print("Commands:")
        print("  help")
        print("  init")
        print("  verify")
