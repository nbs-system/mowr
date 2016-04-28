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

    @staticmethod
    def get_all():
        return Tag.query.all()

    def format(self):
        return '<a class="label label-' + self.color + '" href="#">' + self.name + '</a>'
