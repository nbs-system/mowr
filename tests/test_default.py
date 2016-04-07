from mowr import create_app
from mowr.model.db import Sample
import unittest
import os
from io import BytesIO as StringIO

class DefaultTestCase(unittest.TestCase):
    def setUp(self):
        app = create_app('../tests/config_test.cfg')
        self.config = app.config
        self.app = app.test_client()
        # Clean database if already exists
        Sample.drop_collection()
        # Remove files from test folder
        for f in os.listdir(app.config['UPLOAD_FOLDER']):
            # Dont delete any file, just sha256 looking one (in cas of configuration mistake)
            if len(f) == 64:
                os.remove('{0}/{1}'.format(app.config['UPLOAD_FOLDER'], f))


    def test_upload(self):
        """ Test upload form """
        # Upload without any file
        rv = self.app.post('/upload', follow_redirects=True).data.decode('utf-8')
        self.assertTrue('There was an error while uploading the file. Please try with a different file.' in rv)

        # Upload a malicious php file
        file_content = "<?php@eval($_GET['p'])\
            <?php assert($_GET['p'])\
            $func='test';$b374k=$func('$x', 'ev'.'al')\
            $b=$W('',$S);$b();\
            ;$pouet($pif,$paf);\
            ${$pouet}\
            'pouet'.'pif' . 'pouet' . 'lol' .'kwainkwain'".encode('utf-8')
        file_name = "obfuscated.php"
        rv = self.app.post('/upload', data=dict(
            file=(StringIO(file_content), file_name),
            filename=file_name
        ), follow_redirects=True).data.decode('utf-8')
        self.assertTrue(file_name in rv)
        self.assertTrue('ObfuscatedPhp' in rv)
        self.assertTrue('DodgyPhp' in rv)

        # Upload the same file and check redirection
        rv = self.app.post('/upload', data=dict(
            file=(StringIO(file_content), file_name),
            filename=file_name
        ), follow_redirects=True).data.decode('utf-8')
        self.assertTrue('This file has already been analysed.' in rv)

    def test_checkfile(self):
        self.assertEqual(self.app.get('/file/NON-EXISTANT_SHA').data.decode('utf-8'), 'NOK')

if __name__ == '__main__':
    unittest.main()
