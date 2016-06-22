import hashlib
import os
import shutil
import zipfile
import logging

from flask import flash, current_app

from mowr.lib.analyzers import Analyser
from mowr.models.sample import Sample

MAX_SIZE = 1024 * 1024 * 15

# TODO Not really an analyser maybe it should be moved somewhere else
class ArchiveAnalyser(object):
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
                flash('The size of the archive\'s content is too big !', 'danger')
                return False
            elif compressed_file.filename.lower().endswith('.' + self.analysis.lower()):
                path = archive.extract(compressed_file, current_app.config.get('UPLOAD_FOLDER'))
                with open(path, 'rb') as f:
                    buf = f.read()
                sha256 = hashlib.sha256(buf).hexdigest()
                new_path = Sample.get_file_path(sha256)
                directory = os.path.dirname(new_path)
                try:
                    # Make sure the directory is writeable
                    if not os.access(directory, os.W_OK):
                        try:
                            os.mkdir(directory)
                        except OSError:
                            flash('There was an error while saving you archive.', 'danger')
                    shutil.move(path, new_path)
                except Exception as err:
                    flash('There was an error while extracting your archive', 'danger')
                    logging.error(err)
                    return False

                # Chmod the file to prevent it from being executed
                os.chmod(new_path, 0o400)

                Analyser(sha256=sha256, name=compressed_file.filename, analysis_type=self.analysis, analyse=True)

        return True
