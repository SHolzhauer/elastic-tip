import unittest
from ioc import Intel


class MyTestCase(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, True)

    def test_add_ip(self):
        intel = Intel()
        intel.add_ip(ip="1.1.1.1")
        self.assertEqual(intel.intel["threat"]["indicator"]["ip"], "1.1.1.1")
        intel = Intel()
        intel.add_ip(ip="1.1.1.1", port=443)
        self.assertEqual(intel.intel["threat"]["indicator"]["ip"], "1.1.1.1")
        self.assertEqual(intel.intel["threat"]["indicator"]["port"], 443)

    def test_add_ip(self):
        intel = Intel()
        intel.add_ip(ip="1.1.1.1")
        self.assertEqual(intel.intel["threat"]["indicator"]["ip"], "1.1.1.1")
        intel = Intel()
        intel.add_ip(ip="1.1.1.1", port=443)
        self.assertEqual(intel.intel["threat"]["indicator"]["ip"], "1.1.1.1")
        self.assertEqual(intel.intel["threat"]["indicator"]["port"], 443)

    def test_add_malware(self):
        intel = Intel()
        intel.add_malware(name="Rake")
        self.assertEqual(intel.intel["threat"]["malware"]["name"], "Rake")
        intel = Intel()
        intel.add_malware("Rake")
        self.assertEqual(intel.intel["threat"]["malware"]["name"], "Rake")
        intel = Intel()
        intel.add_malware(name="Rake", family="Rake", malware_type="C&C")
        self.assertEqual(intel.intel["threat"]["malware"]["name"], "Rake")
        self.assertEqual(intel.intel["threat"]["malware"]["family"], "Rake")
        self.assertEqual(intel.intel["threat"]["malware"]["type"], "C&C")

    def test_add_file(self):
        intel = Intel()
        intel.add_file(name="example.exe")
        self.assertEqual(intel.intel["file"]["name"], "example.exe")
        intel = Intel()
        intel.add_file(name="example.exe", sha1="04ea0d99e724bae38f63b34955a669a13da65485",
                       sha256="4d6feee47b15e24f526f8d9053b04a6ff5cefef4f9df71b8dffede2de31fcc57")
        self.assertEqual(intel.intel["file"]["name"], "example.exe")
        self.assertEqual(intel.intel["file"]["hash"]["sha1"], "04ea0d99e724bae38f63b34955a669a13da65485")
        self.assertEqual(intel.intel["file"]["hash"]["sha256"], "4d6feee47b15e24f526f8d9053b04a6ff5cefef4f9df71b8dffede2de31fcc57")
        intel = Intel()
        intel.add_file(name="example.exe", sha1="04ea0d99e724bae38f63b34955a669a13da65485",
                       sha256="4d6feee47b15e24f526f8d9053b04a6ff5cefef4f9df71b8dffede2de31fcc57",
                       drive_letter="C")
        self.assertEqual(intel.intel["file"]["name"], "example.exe")
        self.assertEqual(intel.intel["file"]["drive_letter"], "C")
        self.assertEqual(intel.intel["file"]["hash"]["sha1"], "04ea0d99e724bae38f63b34955a669a13da65485")
        self.assertEqual(intel.intel["file"]["hash"]["sha256"],
                         "4d6feee47b15e24f526f8d9053b04a6ff5cefef4f9df71b8dffede2de31fcc57")

    def test_add_url(self):
        intel = Intel()
        intel.add_url(original="https://test.domain.com:9500/")
        self.assertEqual(intel.intel["url"]["original"], "https://test.domain.com:9500/")
        self.assertEqual(intel.intel["url"]["scheme"], "https")
        intel.add_url(full="https://test.domain.com:9500/")
        self.assertEqual(intel.intel["url"]["original"], "https://test.domain.com:9500/")
        self.assertEqual(intel.intel["url"]["full"], "https://test.domain.com:9500/")
        self.assertEqual(intel.intel["url"]["scheme"], "https")

    def test_add_tls(self):
        intel = Intel()
        intel.add_tls(s_sha1="8964f9caf2c4e688a395f4666db072b165f9c28e")
        self.assertEqual(intel.intel["tls"]["server"]["hash"]["sha1"], "8964f9caf2c4e688a395f4666db072b165f9c28e")


if __name__ == '__main__':
    unittest.main()
