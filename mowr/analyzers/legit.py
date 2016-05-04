import hashlib
import os

import zipfile
import shutil
from flask import flash, current_app

from mowr.analyzers.analyser import Analyser

MAX_SIZE = 1024 * 1024 * 15


class Legit(object):
    def __init__(self, path, analysis):
        self.path = path
        self.analysis = analysis or 'PHP'

    def analyse(self):
        if not zipfile.is_zipfile(self.path):
            flash('The file you sent is not a valid zip file.', 'danger')
            return False

        archive = zipfile.ZipFile(self.path)
        size = 0
        for compressed_file in archive.infolist():
            size += compressed_file.file_size
            if size > MAX_SIZE:
                flash("The size of the archive's content is too big !", 'danger')
                return False
            elif compressed_file.filename.lower().endswith('.' + self.analysis.lower()):
                path = archive.extract(compressed_file, current_app.config.get('UPLOAD_FOLDER'))
                with open(path, 'rb') as f:
                    buf = f.read()
                sha256 = hashlib.sha256(buf).hexdigest()
                new_path = os.path.join(current_app.config.get('UPLOAD_FOLDER'), sha256)
                shutil.move(path, new_path)
                Analyser(sha256=sha256, name=compressed_file.filename, analysis_type=self.analysis, analyse=True)

        return True
