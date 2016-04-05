from mowr import create_app
import unittest
import six

class DefaultTestCase(unittest.TestCase):
    def setUp(self):
        app = create_app('../config.cfg')
        self.app = app.test_client()

    def test_checkfile(self):
        if six.PY2:
            self.assertEqual(self.app.get('/file/NON-EXISTANT_SHA').data, 'NOK')
        else:
            self.assertEqual(self.app.get('/file/NON-EXISTANT_SHA').data, b'NOK')

if __name__ == '__main__':
    unittest.main()
