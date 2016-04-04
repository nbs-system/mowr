from mowr import create_app
import unittest

class DefaultTestCase(unittest.TestCase):
    def setUp(self):
        app = create_app('../config.cfg')
        self.app = app.test_client()

    def test_checkfile(self):
        self.assertEqual(self.app.get('/file/NON-EXISTANT_SHA').data, 'NOK')

if __name__ == '__main__':
    unittest.main()
