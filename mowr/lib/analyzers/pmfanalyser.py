import os
import time
import yara

from flask import current_app, flash

from mowr.models.analysis import Analysis
from mowr.models.sample import Sample


class PmfAnalyser(Analysis):
    types = ['PHP', 'ASP']
    path = ""

    @classmethod
    def load(cls, app):
        """ Returns True if the software can be used """
        if os.access('/etc/phpmalwarefinder', os.R_OK):
            cls.path = '/etc/phpmalwarefinder/'
            if (os.access('/etc/phpmalwarefinder/common.yar', os.R_OK)
                and os.access('/etc/phpmalwarefinder/whitelist.yar', os.R_OK)
                and os.access('/etc/phpmalwarefinder/asp.yar', os.R_OK)
                and os.access('/etc/phpmalwarefinder/php.yar', os.R_OK)):
                return True
        elif os.access(os.path.join(app.config.get('BASE_DIR'), 'php-malware-finder/php-malware-finder'), os.R_OK):
            cls.path = os.path.join(app.config.get('BASE_DIR'), 'php-malware-finder/php-malware-finder')
            if (os.access(os.path.join(cls.path, 'common.yar'), os.R_OK)
                and os.access(os.path.join(cls.path, 'whitelist.yar'), os.R_OK)
                and os.access(os.path.join(cls.path, 'asp.yar'), os.R_OK)
                and os.access(os.path.join(cls.path, 'php.yar'), os.R_OK)):
                return True
        return False

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
