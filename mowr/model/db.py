from flask_mongoengine import Document
import datetime
from mongoengine import StringField, ListField, IntField, DateTimeField


class Sample(Document):
    first_analysis = DateTimeField(required=True, default=datetime.datetime.utcnow())
    last_analysis = DateTimeField(required=True, default=datetime.datetime.utcnow())
    name = ListField(max_length=20)
    md5 = StringField(max_length=32)
    sha256 = StringField(max_length=64)
    ssdeep = StringField()
    pmf_analysis = ListField()
    vote_clean = IntField()
    vote_malicious = IntField()
    mime = StringField(max_length=25)
