import six
from sqlalchemy.orm import validates

from mowr import db

tags = db.Table('tags',
                db.Column('tag_id', db.Integer, db.ForeignKey('tag.id')),
                db.Column('sample_sha256', db.String, db.ForeignKey('sample.sha256'))
                )


def get_tags_table():
    return tags


class Tag(db.Model):
    __tablename__ = 'tag'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(25), unique=True)
    color = db.Column(db.String(10))

    def __init__(self, name, color):
        self.name = name
        self.color = color

    def __str__(self):
        return '<a class="label label-' + self.color + '" href="#">' + self.name + '</a>'

    @validates('name')
    def format_name(self, key, name):
        return name[:25]

    @validates('color')
    def validate_color(self, key, color):
        color = six.moves.urllib.parse.quote(color)
        return color[:10]

    @staticmethod
    def get_all():  # Should stay static
        return Tag.query.all()

    @staticmethod
    def get(id):
        return Tag.query.filter_by(id=id).first()
