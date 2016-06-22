import datetime
import importlib

from flask import session, flash, current_app
from sqlalchemy.exc import DataError

from mowr import db
from mowr.models.sample import Sample


class Analyser(object):
    def __init__(self, sha256, name=None, analysis_type=None, analyse=False):
        self.name = [name]
        self.sha256 = sha256
        self.type = analysis_type
        if analyse:
            self.analyse()

    def analyse(self):
        # New sample ? New analysis ?
        sample = Sample.get(self.sha256)
        if sample is None:
            # New sample, let's add it !
            sample = Sample(sha256=self.sha256, name=self.name)
            sample.compute_hashes()
        else:
            # Too recent do not analyse it
            if sample.last_analysis < (sample.last_analysis + datetime.timedelta(days=3)):
                return True
            # Update last analysis date
            sample.last_analysis = datetime.date.today()
        self.do_analyzes(sample)
        db.session.add(sample)

        # Commit database
        try:
            db.session.commit()
        except DataError:
            flash('There was an error while analysing your file.', 'danger')
            return False

        # Allow the user to vote for his sample
        session['can_vote'] = self.sha256
        return True

    def do_analyzes(self, sample):
        # Already have analysis ? Delete it.
        if sample.analyzes is not None:
            for analysis in sample.analyzes:
                db.session.delete(analysis)
            db.session.commit()
        for analyser in current_app.config.get('ENABLED_ANALYZERS'):
            mod = importlib.import_module("mowr.lib.analyzers." + analyser.lower())
            cls = getattr(mod, analyser)
            if self.type in cls.types:
                sample.analyzes.append(cls(self.type, self.sha256))

    @staticmethod
    def add_name(sha256, name):
        """
        Add a name to the specified sample
        :param sha256: str
        :param name: str
        """
        sample = Sample.get(sha256=sha256)
        if name not in sample.name:  # Since name is an ARRAY (postgresql) we cannot use append()
            sample.name = sample.name + [name]
            db.session.add(sample)
            db.session.commit()
