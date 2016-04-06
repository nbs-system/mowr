from flask_mongoengine import Document
from mongoengine import StringField, ListField


class Sample(Document):
    first_analysis = StringField(max_length=24, required=True)
    last_analysis = StringField(max_length=24, required=True)
    name = ListField(max_length=20)
    md5 = StringField(max_length=32)
    sha256 = StringField(max_length=64)
    ssdeep = StringField()
    pmf_analysis = ListField()