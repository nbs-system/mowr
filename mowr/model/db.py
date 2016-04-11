from flask_mongoengine import Document
import datetime
from mongoengine import StringField, ListField, IntField, DateTimeField, FloatField


class Sample(Document):
    first_analysis = DateTimeField(required=True, default=datetime.datetime.utcnow())
    last_analysis = DateTimeField(required=True, default=datetime.datetime.utcnow())
    name = ListField(StringField(), maxlength=20)
    md5 = StringField(max_length=32)
    sha256 = StringField(max_length=64)
    ssdeep = StringField()
    pmf_analysis = ListField()
    analysis_time = FloatField(default=0)
    vote_clean = IntField(default=0)
    vote_malicious = IntField(default=0)
    mime = StringField(max_length=25)
