import datetime
import hashlib
import os
from collections import Counter

import magic
import math
import ssdeep
from flask import current_app, flash
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import validates

from mowr import db
from mowr.models.tag import tags


class Sample(db.Model):
    __tablename__ = 'sample'
    sha256 = db.Column(db.String(64), primary_key=True)
    name = db.Column(ARRAY(db.String()))
    md5 = db.Column(db.String(32))
    sha1 = db.Column(db.String(40))
    ssdeep = db.Column(db.String)
    entropy = db.Column(db.Float)
    first_analysis = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    last_analysis = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    vote_clean = db.Column(db.Integer, default=0)
    vote_malicious = db.Column(db.Integer, default=0)
    mime = db.Column(db.String(50))
    tags = db.relationship('Tag', secondary=tags, backref=db.backref('sample', lazy='dynamic'))
    analyzes = db.relationship('Analysis', back_populates='sample', enable_typechecks=False)

    def __init__(self, sha256=None, name=None, md5=None, sha1=None, ssdeep=None, entropy=None, first_analysis=None,
                 last_analysis=None, vote_clean=None,
                 vote_malicious=None, mime=None):
        self.name = name
        self.vote_malicious = vote_malicious
        self.vote_clean = vote_clean
        self.last_analysis = last_analysis
        self.entropy = entropy
        self.first_analysis = first_analysis
        self.ssdeep = ssdeep
        self.mime = mime
        self.sha1 = sha1
        self.md5 = md5
        self.sha256 = sha256
        self.name = name

    @validates('mime')
    def validate(self, key, mime):
        if mime is None:
            return mime
        return mime[:50]

    @staticmethod
    def get_file_path(sha256sum):
        """ Return the FileSystem path to the current sample """
        return os.path.join(current_app.config.get('UPLOAD_FOLDER'), sha256sum)

    @staticmethod
    def get(sha256):
        """ Get the sample having this sha256
        :rtype: Sample
        :return Sample: If sha256 already in database
        :return None: If not found
        """
        return Sample.query.filter_by(sha256=sha256).first()

    def compute_hashes(self):
        """ Compute the file hashes """
        self.filename = self.get_file_path(self.sha256)

        # Make sure the file exists and is readable
        if not os.access(self.filename, os.R_OK):
            flash('There was an error while trying to analyse the file.', 'danger')
            return False

        with open(self.filename, 'rb') as f:
            buf = f.read()

        if self.sha256 is None:
            self.sha256 = hashlib.sha256(buf).hexdigest()
        if self.sha1 is None:
            self.sha1 = hashlib.sha1(buf).hexdigest()
        if self.md5 is None:
            self.md5 = hashlib.md5(buf).hexdigest()
        if self.ssdeep is None:
            self.ssdeep = ssdeep.hash(buf)
        if self.mime is None:
            self.mime = magic.from_buffer(buf, mime=True).decode('utf-8')
        if self.entropy is None:
            self.entropy = self.compute_entropy(buf)

    def compute_entropy(self, buf):
        """ Compute Shanon's entropy ( https://rosettacode.org/wiki/Entropy#Python:_More_succinct_version )
        :param str or byte buf: The thing on which we compute the entropy
        :return int : Shanon's entropy of `buf`
        """
        p, lns = Counter(buf), float(len(buf))
        return -sum(count / lns * math.log(count / lns, 2) for count in p.values())
