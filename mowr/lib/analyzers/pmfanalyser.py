import os
import time
import yara

from flask import current_app, flash

from mowr.models.analysis import Analysis
from mowr.models.sample import Sample


class PmfAnalyser(Analysis):
    path = "php-malware-finder/php-malware-finder/"
    binary = "phpmalwarefinder"
    types = ['PHP', 'ASP']

    def __init__(self, analysis_type, filename):
        self.type = analysis_type
        self.soft = 'PMF'
        self.filename = filename
        self.analyse()

    def analyse(self):
        """ Analyse the file with PMF """
        start = time.time()
        rule_file = os.path.join(current_app.config.get('BASE_DIR'), self.path, self.type.lower() + '.yar')
        rules = yara.compile(rule_file)

        try:
            with open(Sample.get_file_path(self.filename), 'rb') as f:
                matches = rules.match(data=f.read())
        except OSError:
            flash('Error while reanalysing the file.', 'danger')
            return False

        self.analysis_time = time.time() - start
        self.result = ' '.join(map(str, matches))
        return True
