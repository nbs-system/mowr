import os
import time
import yara

from flask import current_app, flash

from mowr.models.analysis import Analysis
from mowr.models.sample import Sample


class PmfAnalyser(Analysis):
    def __init__(self, analysis_type, sha256):
        self.type = analysis_type
        self.soft = 'PMF'
        self.sample_sha256 = sha256
        self.analyse()

    def analyse(self):
        """ Analyse the file with PMF """
        start = time.time()
        rule_file = os.path.join(current_app.config.get('PMF_PATH'), self.type.lower() + '.yar')
        rules = yara.compile(rule_file)

        try:
            with open(Sample.get_file_path(self.sample_sha256), 'rb') as f:
                matches = rules.match(data=f.read())
        except OSError:
            flash('Error while reanalysing the file.', 'danger')
            return False

        self.analysis_time = time.time() - start
        self.result = ' '.join(map(str, matches))
        return True
