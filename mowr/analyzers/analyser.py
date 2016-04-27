from flask import session

from mowr import db
from mowr.analyzers.pmfanalyser import PmfAnalyser
from mowr.models.sample import Sample


class Analyser(object):
    def __init__(self, sha256, type=None, name=None):
        self.name = [name]
        self.sha256 = sha256
        self.type = type

    def analyse(self):
        """ Analyse the sample """
        analysis = PmfAnalyser(self.type, self.sha256)

        # New sample ? New analysis ?
        sample = Sample.get(self.sha256)
        if sample is None:
            # New sample, let's add it !
            sample = Sample(sha256=self.sha256, name=self.name)
            sample.compute_hashes()
            sample.analyzes.append(analysis)
            db.session.add(sample)
        else:
            # Update already existing analysis
            for anal in sample.analyzes:
                if anal.type == self.type:
                    anal.result = analysis.result
                    anal.analysis_time = analysis.analysis_time
                    break
            else:  # Or add the new analysis
                sample.analyzes.append(analysis)

        # Commit database
        db.session.commit()

        # Allow the user to vote for his sample
        session['can_vote'] = self.sha256
        return True

    @staticmethod
    def add_name(sha256, name):
        """
        Add a name to the specified sample
        :param sha256: str
        :param name: str
        """
        sample = Sample.get(sha256=sha256)
        if name not in sample.name:
            sample.name = sample.name + [name]
            db.session.add(sample)
            db.session.commit()
