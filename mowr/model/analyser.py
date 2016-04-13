import subprocess
from datetime import datetime
import hashlib
import ssdeep
from flask import current_app, flash, session
from os import access, R_OK
from mowr.model.db import Sample, Analysis
from time import time
from werkzeug.utils import secure_filename
import magic


class Analyser:
    def __init__(self, sha256, filename='', type=None):
        self.sha256 = sha256
        self.filename = secure_filename(filename)
        self.type = self.check_type(type)
        self.file = self.getfilepath(self.sha256)

    @staticmethod
    def getfilepath(sha256sum):
        """ Return the FileSystem path to the current sample """
        return '{0}/{1}'.format(current_app.config['UPLOAD_FOLDER'], sha256sum)

    @staticmethod
    def check_type(type):
        types = current_app.config.get('FILETYPES')
        return type if type in types else types[0]

    def analyse(self):
        #TODO Refactor this function too ugly
        """ Analyse a file and store the analysis result in the database """
        # Make sure the file exists and is readable
        if not access(self.file, R_OK):
            flash('There was an error while trying to analyse the file.', 'danger')
            return False

        # Check if it is a new sample or not
        if not self.getsample():
            # New sample so compute hashes
            with open(self.file, 'rb') as f:
                buf = f.read()
            sha256sum = hashlib.sha256(buf).hexdigest()
            if sha256sum != self.sha256:
                print("Sorry but it seems the hash I got is different from the one I computed !")
            self.sha256 = sha256sum
            md5sum = hashlib.md5(buf).hexdigest()
            ssdeephash = ssdeep.hash(buf)
            mime = magic.from_buffer(buf, mime=True).decode('utf-8')

        # Start time counter
        start = time()

        # Cut filename
        filename = self.filename[:75]

        # Start the analysis
        # TODO yara bindings ?
        if self.type == 'ASP':
            pmf = subprocess.check_output([current_app.config['PMF_BIN'], '-l', 'asp', self.file])
            pmf = [v for i, v in list(enumerate(pmf.decode('utf-8').split())) if i % 2 == 0]
        else:
            pmf = subprocess.check_output([current_app.config['PMF_BIN'], self.file])
            pmf = [v for i, v in list(enumerate(pmf.decode('utf-8').split())) if i % 2 == 0]

        # End time counter
        end = time()
        analysis_time = end-start

        # Create analysis embedded document
        analysis = Analysis(
            soft='PMF',
            analysis_time=analysis_time,
            type=self.type,
            result=pmf
        )

        if not self.getsample():
            sample = Sample(
                first_analysis=datetime.utcnow(),
                last_analysis=datetime.utcnow(),
                name=[filename],
                md5=md5sum,
                sha256=self.sha256,
                ssdeep=ssdeephash,
                vote_clean=0,
                vote_malicious=0,
                mime=mime
            )
            sample.analyzes.append(analysis)
            sample.save()
        else:
            sample = Sample.objects(sha256=self.sha256).first()
            updated = False
            # Update already existing analysis
            for anal in sample.analyzes:
                if anal.type == analysis.type and anal.soft == analysis.soft:
                    a = sample.analyzes.filter(soft=analysis.soft, type=analysis.type).first()
                    a.result = analysis.result
                    a.analysis_time = analysis.analysis_time
                    sample.save()
                    updated = True
                    break

            # Or add the new analysis
            if not updated:
                sample.analyzes.append(analysis)
                sample.save()

        # Allow the user to vote for his sample
        session['can_vote'] = self.sha256
        return True

    def getsample(self):
        """ Return the Sample object (database row) """
        return Sample.objects(sha256=self.sha256).first()

    def addname(self, filename):
        """ Add a name to the sample in the database """
        if filename is not None:
            Sample.objects(sha256=self.sha256).first().update(add_to_set__name=filename)
