import unittest

import datetime

from mowr import create_app, db
from mowr.models.sample import Sample
from mowr.models.analysis import Analysis


class AdminTestCase(unittest.TestCase):
    def setUp(self):
        app = create_app('../tests/config_test.cfg')
        self.config = app.config
        self.app = app.test_client()

    def login(self):
        return self.app.post('/admin/login', data=dict(
            login=self.config.get('ADMIN_LOGIN'),
            password=self.config.get('ADMIN_PASSWORD')
        )).data.decode('utf-8')

    def test_login(self):
        """ Test login form """
        # Upload without any data
        rv = self.app.post('/admin/login', follow_redirects=True).data.decode('utf-8')
        self.assertTrue('Sorry, are you sure about what you are doing ?' in rv)

        # Insert wrong username/password
        rv = self.app.post('/admin/login', data=dict(
            login='wut',
            password='wutwut'
        ), follow_redirects=True).data.decode('utf-8')
        self.assertTrue('Sorry, are you sure about what you are doing ?' in rv)

        # Login with correct password
        rv = self.login()
        self.assertTrue('You should be redirected automatically to target URL: <a href="/admin/">/admin/</a>' in rv)

        # Try to connect while already connected
        rv = self.app.post('/admin/login').data.decode('utf-8')
        self.assertTrue('You should be redirected automatically to target URL: <a href="/admin/">/admin/</a>' in rv)

    def test_logout(self):
        """ Test logout form """
        # Login first
        self.login()
        self.app.get('/admin/logout')
        rv = self.app.get('/admin/').data.decode('utf-8')
        self.assertTrue(
            'You should be redirected automatically to target URL: <a href="/admin/login">/admin/login</a>' in rv)

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
        self.assertTrue('You should be redirected automatically to target URL: <a href="/admin/login">/admin/login</a>' in rv)

        # Log in and access it
        self.login()
        rv = self.app.get('/admin/').data.decode('utf-8')
        dates = [datetime.date.today() - datetime.timedelta(days=x) for x in range(7)]
        dates = [date.isoformat() for date in reversed(dates)]
        self.assertTrue("labels: " + str(dates) + "," in rv)

