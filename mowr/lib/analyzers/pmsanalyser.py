import os
import time
import subprocess

from mowr.models.analysis import Analysis
from mowr.models.sample import Sample


class PmsAnalyser(Analysis):
    path = "php-malware-scanner/"
    binary = "phpscanner.py"
    types = ['PHP']

    def __init__(self, analysis_type, filename):
        self.type = analysis_type
        self.soft = 'PMS'
        self.filename = filename
        self.analyse()

    def analyse(self):
        """ Analyse the file with PMF """
        start = time.time()
        args = ["python2", os.path.join(self.path, self.binary), Sample.get_file_path(self.filename)]
        proc = subprocess.Popen(args, stdout=subprocess.PIPE)
        content = ''
        for line in proc.stdout:
            content += line
        self.analysis_time = time.time() - start
        if len(content) < 5:
            content = ''
        self.result = content
        return True
