import os
import unittest

import datetime

from io import BytesIO as StringIO

from mowr import create_app, db
from mowr.models.sample import Sample
from mowr.models.analysis import Analysis
from mowr.models.tag import Tag

zip_archive = bytearray.fromhex('504b0304140000000800138ea348c21263f94d0000007a0000000c001c00'
                                '62797061737365732e706870555409000355c828575ec8285775780b0001'
                                '04e803000004e8030000b3b12fc82850e02a28cacc2b892fd2484eccc989'
                                '2f2d4e2d8a4f2bcd4b8e4f2c2a4aacd450890ff00f0e895607099564a6aa'
                                'c7ea28a04a2416a597a9c76a6a6a5ac30d42d1a31e8ba1d49a0b00504b01'
                                '021e03140000000800138ea348c21263f94d0000007a0000000c00180000'
                                '00000001000000a4810000000062797061737365732e7068705554050003'
                                '55c8285775780b000104e803000004e8030000504b050600000000010001'
                                '0052000000930000000000')


class AdminTestCase(unittest.TestCase):
    def setUp(self):
        app = create_app('../tests/config_test.cfg')
        self.config = app.config
        self.app = app.test_client()

    def login(self):
        return self.app.post('/login', data=dict(
            login=self.config.get('ADMIN_LOGIN'),
            password=self.config.get('ADMIN_PASSWORD')
        )).data.decode('utf-8')

    def test_login(self):
        """ Test login form """
        # Upload without any data
        rv = self.app.post('/login', follow_redirects=True).data.decode('utf-8')
        self.assertIn('Sorry, are you sure about what you are doing ?', rv)

        # Insert wrong username/password
        rv = self.app.post('/login', data=dict(
            login='wut',
            password='wutwut'
        ), follow_redirects=True).data.decode('utf-8')
        self.assertIn('Sorry, are you sure about what you are doing ?', rv)

        # Login with correct password
        rv = self.login()
        self.assertIn('You should be redirected automatically to target URL: <a href="/admin/">/admin/</a>', rv)

        # Try to connect while already connected
        rv = self.app.post('/login').data.decode('utf-8')
        self.assertIn('You should be redirected automatically to target URL: <a href="/admin/">/admin/</a>', rv)

    def test_logout(self):
        """ Test logout form """
        # Login first
        self.login()
        self.app.get('/admin/logout')
        rv = self.app.get('/admin/').data.decode('utf-8')
        self.assertIn(
            'You should be redirected automatically to target URL: <a href="/login">/login</a>', rv)

    def test_index(self):
        """ Test admin index """
        # Add a sample in the database
        sample = Sample(
            sha256='6ffef45e178b189c9eb486457dc6ae71a2e62be5724adc598d25585a6c0c6c1a',
            sha1='6a6f0260611dcd60d502d308f74ff3c1ad590cfe',
            md5='149b8ae3ca1cf126af05bd8c58ebde90',
            ssdeep='3072:7Q6vU3oUXNiDarHituutTxmakBIRDzGoiTzj7c5hH5D8:7Q6vMXNQarHituutTxmakBcDzGoiTzjF',
            entropy='5.65471943656401',
            mime='text/x-php',
            first_analysis='2000-01-01 10:00:00.00000',
            last_analysis='2000-01-01 10:00:00.00000'
        )
        sample.analyzes.append(Analysis(
            type='PHP',
            soft='PMF',
            sample_sha256='6ffef45e178b189c9eb486457dc6ae71a2e62be5724adc598d25585a6c0c6c1a',
            analysis_time='0.004575014114379883'
        ))
        db.session.add(sample)
        db.session.commit()

        # Access without being logged in
        rv = self.app.get('/admin/').data.decode('utf-8')
        self.assertIn('You should be redirected automatically to target URL: <a href="/login">/login</a>',
                      rv)

        # Log in and access it
        self.login()
        rv = self.app.get('/admin/').data.decode('utf-8')
        dates = [datetime.date.today() - datetime.timedelta(days=x) for x in range(7)]
        dates = [date.isoformat() for date in reversed(dates)]
        self.assertIn("labels: " + str(dates) + ",", rv)

    def test_samples(self):
        # Access the page with no authentication
        rv = self.app.get('/admin/samples').data.decode('utf-8')
        self.assertIn('You should be redirected automatically to target URL: <a href="/login">/login</a>',
                      rv)

        # Log in
        self.login()
        rv = self.app.get('/admin/samples').data.decode('utf-8')
        self.assertIn('<h2>Search</h2>', rv)

    def test_whitelist(self):
        # Access the page with no authentication
        rv = self.app.get('/admin/whitelist').data.decode('utf-8')
        self.assertIn('You should be redirected automatically to target URL: <a href="/login">/login</a>',
                      rv)

        # Log in
        self.login()
        rv = self.app.get('/admin/whitelist').data.decode('utf-8')
        self.assertIn('<h2>Whitelist</h2>', rv)

        # Post a file
        # With no file
        rv = self.app.post('/admin/whitelist', data=dict(
            filename='fn',
            type='PHP'
        ), follow_redirects=True).data.decode('utf-8')
        self.assertIn('Please select a valid file.', rv)

        # With no type
        rv = self.app.post('/admin/whitelist', data=dict(
            file=(StringIO(b'waoh'), 'fn'),
            filename='fn'
        ), follow_redirects=True).data.decode('utf-8')
        self.assertIn('The file you sent is not a valid zip file.', rv)

        # Correct zip file
        rv = self.app.post('/admin/whitelist', data=dict(
            file=(StringIO(zip_archive), 'samples.zip'),
            filename='samples.zip',
            type='PHP'
        ), follow_redirects=True).data.decode('utf-8')
        self.assertFalse(os.access(os.path.join(self.config.get('UPLOAD_FOLDER'), 'samples.zip'), os.R_OK))
        self.assertTrue(os.access(os.path.join(self.config.get('UPLOAD_FOLDER'),
                                               'f16a149d97127fdf6280ac92df82dfca266a476a0d5df559693ec2c31898a7b5'),
                                  os.R_OK))

    def test_tags(self):
        # Access the page with no authentication
        rv = self.app.get('/admin/tags').data.decode('utf-8')
        self.assertIn('You should be redirected automatically to target URL: <a href="/login">/login</a>',
                      rv)

        # Log in
        self.login()
        rv = self.app.get('/admin/tags').data.decode('utf-8')
        self.assertIn('<h2>Tags</h2>', rv)

    def test_add_tag(self):
        # Delete all tags
        [db.session.delete(tag) for tag in Tag.get_all()]
        db.session.commit()

        # Access the page with no authentication
        rv = self.app.get('/admin/tags/add').data.decode('utf-8')
        self.assertIn('You should be redirected automatically to target URL: <a href="/login">/login</a>',
                      rv)
        # Log in
        self.login()
        rv = self.app.get('/admin/tags/add').data.decode('utf-8')
        self.assertIn('<h2>Add tag</h2>', rv)

        # Send invalid tag
        name = 'To">xoxowat'
        color = 'fuckingtoolongcolor<3xoxo">'
        rv = self.app.post('/admin/tags/add', data=dict(
            name=name,
            color=color
        ), follow_redirects=True).data.decode('utf-8')
        self.assertIn('<h2>Tags</h2>', rv)
        self.assertIn(name, rv)
        self.assertNotIn(color, rv)
        self.assertIn(color[:10], rv)

    def test_edit_tag(self):
        # Delete all tags
        [db.session.delete(tag) for tag in Tag.get_all()]
        db.session.commit()

        # Add a tag
        db.session.add(Tag('mytag', 'info'))
        db.session.commit()

        tag_id = Tag.query.filter(Tag.name == 'mytag').first().id

        # Access the page with no authentication
        rv = self.app.get('/admin/tags/edit/{id}'.format(id=tag_id)).data.decode('utf-8')
        self.assertIn('You should be redirected automatically to target URL: <a href="/login">/login</a>',
                      rv)

        # Log in
        self.login()
        rv = self.app.get('/admin/tags/edit/{id}'.format(id=tag_id)).data.decode('utf-8')
        self.assertIn('<h2>Edit tag : {id}</h2>'.format(id=tag_id), rv)

        # Acces the page with no id
        rv = self.app.get('/admin/tags/edit/').status_code
        self.assertEqual(rv, 404)

        # Acces the page with invalid id
        rv = self.app.get('/admin/tags/edit/978789987987978897879').status_code
        self.assertEqual(rv, 404)

        # Edit the tag
        name = 'MyTag'
        color = 'danger'
        rv = self.app.post('/admin/tags/edit/{id}'.format(id=tag_id), data=dict(
            name=name,
            color=color
        ), follow_redirects=True).data.decode('utf-8')
        self.assertIn('<h2>Tags</h2>', rv)
        self.assertIn(name, rv)
        self.assertIn('label-danger', rv)

    def test_delete_tag(self):
        # Delete all tags
        [db.session.delete(tag) for tag in Tag.get_all()]
        db.session.commit()

        # Add a tag
        db.session.add(Tag('mytag', 'info'))
        db.session.commit()

        tag_id = Tag.query.filter(Tag.name == 'mytag').first().id
        # Access the page with no authentication
        rv = self.app.get('/admin/tags/delete/{id}'.format(id=tag_id)).data.decode('utf-8')
        self.assertIn('You should be redirected automatically to target URL: <a href="/login">/login</a>',
                      rv)
        # Log in
        self.login()

        # Acces the page with no id
        rv = self.app.get('/admin/tags/delete/').status_code
        self.assertEqual(rv, 404)

        # Acces the page with invalid id
        rv = self.app.get('/admin/tags/delete/978789987987978897879').status_code
        self.assertEqual(rv, 404)

        # Delete the tag
        self.app.get('/admin/tags/delete/{id}'.format(id=tag_id))
        self.assertIsNone(Tag.get(tag_id))
