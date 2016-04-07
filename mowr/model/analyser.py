import subprocess
from datetime import datetime
from hashlib import sha256, md5
import ssdeep
from flask import current_app, flash, session
from os import access, R_OK
from mowr.model.db import Sample
from werkzeug.utils import secure_filename


class Analyser():
    def __init__(self, sha256, filename=''):
        self.sha256 = sha256
        self.filename = secure_filename(filename)
        self.file = self.getfilepath(self.sha256)

    @staticmethod
    def getfilepath(sha256sum):
        """ Return the FileSystem path to the current sample """
        return '{0}/{1}'.format(current_app.config['UPLOAD_FOLDER'], sha256sum)

    def analyse(self):
        """ Analyse a file and store the analysis result in the database """
        # Make sure the file exists and is readable
        if not access(self.file, R_OK):
            flash('There was an error while trying to analyse the file.', 'danger')
            return -1

        # Compute hashes
        with open(self.file, 'rb') as f:
            buf = f.read()
        sha256sum = sha256(buf).hexdigest()
        md5sum = md5(buf).hexdigest()
        ssdeephash = ssdeep.hash(buf)

        # Cut filename
        filename = self.filename[:75]

        # Start the analysis
        # TODO yara bindings ?
        analysis = subprocess.check_output([current_app.config['PMF_BIN'], self.file])
        analysis = [v for i, v in list(enumerate(analysis.decode('utf-8').split())) if i % 2 == 0]

        if not self.getsample():
            Sample(
                first_analysis=datetime.utcnow().ctime(),
                last_analysis=datetime.utcnow().ctime(),
                name=[filename],
                md5=md5sum,
                sha256=sha256sum,
                ssdeep=ssdeephash,
                pmf_analysis=analysis,
                vote_clean=0,
                vote_malicious=0
            ).save()
        else:
            Sample.objects(sha256=self.sha256).first().update(
                last_analysis=datetime.utcnow().ctime(),
                md5=md5sum,
                sha256=sha256sum,
                ssdeep=ssdeephash,
                pmf_analysis=analysis,
                add_to_set__name=filename
            )
            
        # Allow the user to vote for his sample
        session['can_vote'] = sha256sum
        return 0

    def getsample(self):
        """ Return the Sample object (database row) """
        return Sample.objects(sha256=self.sha256).first()

    def addname(self, filename):
        """ Add a name to the sample in the database """
        if filename is not None:
            Sample.objects(sha256=self.sha256).first().update(add_to_set__name=filename)
