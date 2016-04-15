from datetime import datetime
import hashlib
import ssdeep
from flask import current_app, flash, session
from os import access, R_OK
from mowr.model.db import Sample, Analysis
from time import time
from collections import Counter
from werkzeug.utils import secure_filename
import magic
import math
import yara


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
        """ Check the analysis type """
        types = current_app.config.get('FILE_TYPES')
        return type if type in types else types[0]

    def analyse(self):
        """ Analyse a file and store the analysis result in the database """
        # Make sure the file exists and is readable
        if not access(self.file, R_OK):
            flash('There was an error while trying to analyse the file.', 'danger')
            return False

        # Cut filename
        filename = self.filename[:75]

        # Start the analysis
        start = time()
        pmf = self.do_analyse()
        analysis_time = time() - start

        # Create analysis embedded document
        analysis = Analysis(
            analysis_time=analysis_time,
            type=self.type,
            pmf_result=pmf
        )

        if not self.getsample():
            # If new sample, compute its hashes
            (sha256sum, md5sum, ssdeephash, mime, entropy) = self.compute_sample()
            # If new sample insert it
            sample = Sample(
                first_analysis=datetime.utcnow(),
                last_analysis=datetime.utcnow(),
                name=[filename],
                md5=md5sum,
                sha256=self.sha256,
                ssdeep=ssdeephash,
                vote_clean=0,
                vote_malicious=0,
                mime=mime,
                entropy=entropy
            )
            sample.analyzes.append(analysis)
            sample.save()
        else:
            # If not update the sample information
            sample = Sample.objects(sha256=self.sha256).first()
            updated = False

            # Update already existing analysis
            for anal in sample.analyzes:
                if anal.type == analysis.type:
                    a = sample.analyzes.filter(type=analysis.type).first()
                    a.pmf_result = analysis.pmf_result
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

    def compute_sample(self):
        """ Compute everything related to the file itself """
        with open(self.file, 'rb') as f:
            buf = f.read()
        sha256sum = hashlib.sha256(buf).hexdigest()
        if sha256sum != self.sha256:
            print("Sorry but it seems the hash I got is different from the one I computed !")
        self.sha256 = sha256sum
        md5sum = hashlib.md5(buf).hexdigest()
        ssdeephash = ssdeep.hash(buf)
        mime = magic.from_buffer(buf, mime=True).decode('utf-8')
        entropy = self.entropy(buf)
        return sha256sum, md5sum, ssdeephash, mime, entropy

    def do_analyse(self):
        """ Analyse the file with PMF """
        rule_file = '{path}/{rule}.yara'.format(path=current_app.config.get('PMF_PATH'), rule=self.type.lower())
        print(rule_file)
        rules = yara.compile(rule_file)
        with open(self.file, 'rb') as f:
            matches = rules.match(data=f.read())
        return [str(m) for m in matches]

    def getsample(self):
        """ Return the Sample object (database row) """
        return Sample.objects(sha256=self.sha256).first()

    def addname(self, filename):
        """ Add a name to the sample in the database """
        if filename is not None:
            Sample.objects(sha256=self.sha256).first().update(add_to_set__name=filename)

    def entropy(self, buf):
        p, lns = Counter(buf), float(len(buf))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
