from flask_mongoengine import Document
import datetime
from mongoengine import StringField, ListField, IntField, DateTimeField, FloatField, EmbeddedDocumentListField, \
    EmbeddedDocument


class Analysis(EmbeddedDocument):
    soft = StringField(max_length=10, unique_with='type')
    type = StringField(max_length=5, unique=True)
    analysis_time = FloatField(default=0)
    result = ListField()


class Sample(Document):
    first_analysis = DateTimeField(required=True, default=datetime.datetime.utcnow())
    last_analysis = DateTimeField(required=True, default=datetime.datetime.utcnow())
    name = ListField(StringField(), maxlength=20)
    md5 = StringField(max_length=32)
    sha256 = StringField(required=True, max_length=64, unique=True)
    ssdeep = StringField()
    vote_clean = IntField(default=0)
    vote_malicious = IntField(default=0)
    mime = StringField(max_length=25)
    analyzes = EmbeddedDocumentListField(Analysis)
