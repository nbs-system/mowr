import os
import unittest
from io import BytesIO as StringIO

from mowr import create_app
from mowr import db
from mowr.models.tag import Tag
from mowr.models.sample import Sample

file_content = "<?php@eval($_GET['p'])\
    <?php assert($_GET['p'])\
    $func='test';$b374k=$func('$x', 'ev'.'al')\
    $b=$W('',$S);$b();\
    ;$pouet($pif,$paf);\
    ${$pouet}\
    'pouet'.'pif' . 'pouet' . 'lol' .'kwainkwain'".encode('utf-8')
global_content = "<?php@eval($_GET['p'])\
    <?php assert($_GET['p'])\
    $func='test';$b374k=$func('$x', 'ev'.'al')\
    $b=$W('',$S);$b();\
    ;$pouet($pif,$paf);\
    ${$pouet}\
    'pouet'.'pif' . 'pouet' . 'lol' .'imdifferent'".encode('utf-8')
file_name = "obfuscated.php"
file_sha256 = "eee4f6f0fe3b19dfa7a7be1145a36cb79cd4950b8908239f95bd6c0da06a82e9"
global_sha256 = "bcc5bae3bb00316dbededbabb64c922a2b9556c860d78f54887b73f67885c57a"


class DefaultTestCase(unittest.TestCase):
    def setUp(self):
        app = create_app('../tests/config_test.cfg')
        app.debug = True
        self.config = app.config
        self.app = app.test_client()
        # Clean database if already exists
        db.drop_all()
        db.create_all()
        # Remove files from test folder
        for f in os.listdir(app.config['UPLOAD_FOLDER']):
            # Do not delete any file, just sha256 looking one (in case of configuration mistake)
            if len(f) == 64:
                os.remove('{0}/{1}'.format(app.config['UPLOAD_FOLDER'], f))
        # Upload a file
        self.app.post('/upload', data=dict(
            file=(StringIO(global_content), file_name),
            filename=file_name,
            type='PHP'
        ), follow_redirects=True)

    def test_upload(self):
        """ Test upload form """
        # Upload without any file
        rv = self.app.post('/upload', follow_redirects=True).data.decode('utf-8')
        self.assertIn('Please select a valid file.', rv)

        # Upload a file with a wrong type
        rv = self.app.post('/upload', data=dict(
            file=(StringIO(file_content), file_name),
            filename=file_name,
            type='.NET'
        ), follow_redirects=True).data.decode('utf-8')
        self.assertIn('Sorry but the request you sent is invalid.', rv)

        # Upload a malicious php file
        rv = self.app.post('/upload', data=dict(
            file=(StringIO(file_content), file_name),
            filename=file_name,
            type='PHP'
        ), follow_redirects=True).data.decode('utf-8')
        self.assertIn(file_name, rv)
        self.assertIn('ObfuscatedPhp', rv)
        self.assertIn('DodgyPhp', rv)
        self.assertIn(file_sha256, rv)

        # Upload the same file and check redirection
        rv = self.app.post('/upload', data=dict(
            file=(StringIO(file_content), file_name),
            filename=file_name,
            type='PHP'
        ), follow_redirects=True).data.decode('utf-8')
        self.assertIn('This file has already been analysed.', rv)

    def test_sample_exists(self):
        rv = self.app.get('/sample/PHP/NON-EXISTANT_SHA').data.decode('utf-8')
        self.assertEqual(rv, 'NOK')

    def test_analysis(self):
        # Upload a file
        self.app.post('/upload', data=dict(
            file=(StringIO(file_content), file_name),
            filename=file_name,
            type='PHP'
        ), follow_redirects=True)
        rv = self.app.get('/analysis/WAOH/{sha256}'.format(sha256=file_sha256), follow_redirects=True).data.decode('utf-8')
        self.assertIn('ObfuscatedPhp', rv)
        rv = self.app.get('/analysis/PHP/whatasha(me)')
        self.assertEqual(rv.status_code, 404)

    def test_analyse(self):
        # Analyse an already uploaded file
        rv = self.app.get('/analyse/PHP/{sha256}'.format(sha256=global_sha256), follow_redirects=True).data.decode('utf-8')
        self.assertIn('ObfuscatedPhp', rv)

    def test_documentation(self):
        # Get the documentation page and make sure it looks like a documentation page
        rv = self.app.get('/documentation').data.decode('utf-8')
        self.assertIn('<h1>Documentation</h1>', rv)

    def test_submit_tag(self):
        # Submit shitty tag
        rv = self.app.get('/tag/submit/{sha256}/SHITTY').data.decode('utf-8')
        self.assertEqual(rv, 'NOK')

        # Submit a correct tag with invalid sha256
        rv = self.app.get('/tag/submit/{sha256}/Tag').data.decode('utf-8')
        self.assertEqual(rv, 'NOK')

        # Add a tag to the db
        tag = Tag('Tag', 'info')
        db.session.add(tag)
        db.session.commit()

        # Submit a correct tag with valid sha256
        rv = self.app.get('/tag/submit/{sha256}/Tag'.format(sha256=global_sha256)).data.decode('utf-8')
        self.assertEqual(rv, 'OK')
        tags = [tag.name for tag in Sample.get(global_sha256).tags]
        self.assertIn('Tag', tags)

        # Submit the same tag with the same sha256
        rv = self.app.get('/tag/submit/{sha256}/Tag'.format(sha256=global_sha256)).data.decode('utf-8')
        self.assertEqual(rv, 'NOK')

    def test_vote(self):
        # Vote for the file we just uploaded
        rv = self.app.get('/vote/{sha256}/clean'.format(sha256=global_sha256)).data.decode('utf-8')
        samp = Sample.get(global_sha256)
        self.assertEqual(rv, 'OK')
        self.assertEqual(samp.vote_clean, 1)
        self.assertEqual(samp.vote_malicious, 0)

        # Vote for the same file
        rv = self.app.get('/vote/{sha256}/clean'.format(sha256=global_sha256)).data.decode('utf-8')
        samp = Sample.get(global_sha256)
        self.assertEqual(rv, 'NOK')
        self.assertEqual(samp.vote_clean, 1)
        self.assertEqual(samp.vote_malicious, 0)

        # Upload a new file
        self.app.post('/upload', data=dict(
            file=(StringIO(file_content), file_name),
            filename=file_name,
            type='PHP'
        ))

        # Vote for this file
        rv = self.app.get('/vote/{sha256}/malicious'.format(sha256=file_sha256)).data.decode('utf-8')
        samp = Sample.get(file_sha256)
        self.assertEqual(rv, 'OK')
        self.assertEqual(samp.vote_clean, 0)
        self.assertEqual(samp.vote_malicious, 1)

    def test_search(self):
        rv = self.app.get('/search').data.decode('utf-8')
        self.assertIn('bcc5bae3bb00316dbededbabb64c922a2b9556c860d78f54887b73f67885c57a', rv)
        rv = self.app.get('/search/9').status_code
        self.assertEqual(404, rv)
        rv = self.app.get('/search/999999999999999999999999999999999999999999999').status_code
        self.assertEqual(404, rv)
        rv = self.app.get('/search/notanint').status_code
        self.assertEqual(404, rv)


if __name__ == '__main__':
    unittest.main()
