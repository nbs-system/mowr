import unittest

from mowr import create_app
from mowr import db
from mowr.models.analysis import Analysis
from mowr.models.sample import Sample
from mowr.models.tag import Tag


def search(app, query):
    return app.post('/search', data=dict(search=query))


class CommonTestCase(unittest.TestCase):
    def setUp(self):
        app = create_app('../tests/config_test.cfg')
        self.config = app.config
        self.app = app.test_client()
        db.session.close()
        db.drop_all()
        db.create_all()

    def test_search(self):
        rv = self.app.get('/search')
        self.assertEqual(200, rv.status_code)
        self.assertIn('<h1>Search</h1>', rv.data.decode('utf-8'))

        # Add a sample with his tag
        tag = Tag('wat', 'danger')
        db.session.add(tag)
        sample = Sample(
            name=['wut.php'],
            sha256='6ffef45e178b189c9eb486457dc6ae71a2e62be5724adc598d25585a6c0c6c1a',
            sha1='6a6f0260611dcd60d502d308f74ff3c1ad590cfe',
            md5='149b8ae3ca1cf126af05bd8c58ebde90',
            ssdeep='3072:7Q6vU3oUXNiDarHituutTxmakBIRDzGoiTzj7c5hH5D8:7Q6vMXNQarHituutTxmakBcDzGoiTzjF',
            entropy='5.65471943656401',
            mime='text/x-php',
            first_analysis='2000-01-01 10:00:00.00000',
            last_analysis='2000-01-01 10:00:00.00000'
        )
        sample.tags.append(tag)
        sample.analyzes.append(Analysis(
            type='PHP',
            soft='PMF',
            sample_sha256='6ffef45e178b189c9eb486457dc6ae71a2e62be5724adc598d25585a6c0c6c1a',
            analysis_time='0.004575014114379883'
        ))
        db.session.add(sample)
        db.session.commit()
        result_sha256 = '<a href="/analysis/any/6ffef45e178b189c9eb486457dc6ae71a2e62be5724adc598d25585a6c0c6c1a">6ffef45e178b189c9eb486457dc6ae71a2e62be5724adc598d25585a6c0c6c1a</a>'
        rv = self.app.get('/search')
        self.assertIn(result_sha256, rv.data.decode('utf-8'))

        # Custom search
        rv = search(self.app, '6ffe')
        self.assertIn(result_sha256, rv.data.decode('utf-8'))
        rv = search(self.app, '6ffe123')
        self.assertNotIn(result_sha256, rv.data.decode('utf-8'))
        rv = search(self.app, 'md5: 126')
        self.assertIn(result_sha256, rv.data.decode('utf-8'))
        rv = search(self.app, 'md5: wat')
        self.assertNotIn(result_sha256, rv.data.decode('utf-8'))
        rv = search(self.app, 'name: php')
        self.assertIn(result_sha256, rv.data.decode('utf-8'))
        rv = search(self.app, 'name: qweqwe')
        self.assertNotIn(result_sha256, rv.data.decode('utf-8'))
        rv = search(self.app, 'fist_analysis: 2000-01-01')
        self.assertIn(result_sha256, rv.data.decode('utf-8'))
        rv = search(self.app, 'last_analysis: 2000-01-03')
        self.assertNotIn(result_sha256, rv.data.decode('utf-8'))
        rv = search(self.app, 'tags: wat')
        self.assertIn(result_sha256, rv.data.decode('utf-8'))
        rv = search(self.app, 'tags: watt')
        self.assertNotIn(result_sha256, rv.data.decode('utf-8'))
