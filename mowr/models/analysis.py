from mowr import db


class Analysis(db.Model):
    __tablename__ = 'analysis'
    type = db.Column(db.String(5), primary_key=True)
    soft = db.Column(db.String(10), primary_key=True)
    sample_sha256 = db.Column(db.String(64), db.ForeignKey('sample.sha256'), primary_key=True)
    sample = db.relationship('Sample', back_populates='analyzes')
    analysis_time = db.Column(db.Float)
    result = db.Column(db.String)
