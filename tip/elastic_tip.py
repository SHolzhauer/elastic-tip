from abuse_bazaar import URLhaus


class ElasticTip:

    def __init__(self):
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


