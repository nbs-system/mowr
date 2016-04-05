import subprocess
from datetime import datetime
from hashlib import sha256, md5
import ssdeep
from bson.objectid import ObjectId, InvalidId
from flask import abort, current_app, flash
from os import access, R_OK
import six

class Analyser():
    def __init__(self, file=None, id=None, filename=''):
        self.id = id
        self.file = file
        self.filename = filename
        # Check if id is valid
        if id is not None:
            try:
                current_app.mongo.db.files.find_one_or_404({"_id": ObjectId(self.id)})
            except InvalidId:
                abort(404)

        # Get file path
        if self.file is None:
            sha256sum = current_app.mongo.db.files.find_one_or_404({"_id": ObjectId(self.id)})['sha256']
            self.file = self.getFilePath(sha256sum)

    @staticmethod
    def getFilePath(sha256sum):
        return '{0}/{1}'.format(current_app.config['UPLOAD_FOLDER'], sha256sum)

    def analyse(self):
        """ Returns the file _id """
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

        # Start the analysis
        # TODO yara bindings ?
        analysis = subprocess.check_output(
                [current_app.config['PMF_BIN'], self.file]
                )
        if six.PY2:
            analysis = [v for i, v in list(enumerate(analysis.split())) if i%2 == 0]
        else:
            analysis = [v for i, v in enumerate(analysis.decode('utf-8').split()) if i%2 == 0]

        # Max length is 50
        filename = self.filename[:50]

        # Store the result into the database
        if self.id is None:
            data = {"first_analysis": datetime.utcnow().ctime(),
                    "last_analysis": datetime.utcnow().ctime(),
                    "name": [filename],
                    "md5": md5sum,
                    "sha256": sha256sum,
                    "ssdeep": ssdeephash,
                    "pmf_analysis": analysis}
            id = current_app.mongo.db.files.insert_one(data).inserted_id
            self.id = id
        else:
            data = {"last_analysis": datetime.utcnow().ctime(),
                    "md5": md5sum,
                    "sha256": sha256sum,
                    "ssdeep": ssdeephash,
                    "pmf_analysis": analysis}
            current_app.mongo.db.files.update_one({"_id": ObjectId(self.id)}, {"$set": data, "$addToSet": {"name": filename}})

        return self.id

    def getInfos(self):
        """ Get current analysis informations """
        return current_app.mongo.db.files.find_one_or_404({"_id": ObjectId(self.id)})

    def addName(self, filename):
        if filename is None:
            return
        # Check the filename is valid otherwise it's junk
        filename = filename[:50]
        if any(x in filename for x in ['/', '\\', '..', ';', ',']):
            return

        # Insert it into the database
        current_app.mongo.db.files.update_one({"_id": ObjectId(self.id)}, {"$addToSet": {"name": filename}})

