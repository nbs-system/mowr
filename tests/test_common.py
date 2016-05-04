import unittest

from mowr import create_app


class CommonTestCase(unittest.TestCase):
    def setUp(self):
        app = create_app('../tests/config_test.cfg')
        self.config = app.config
        self.app = app.test_client()

    def test_search(self):
        self.app.get('')
