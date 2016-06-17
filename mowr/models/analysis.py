from sqlalchemy.orm import validates

from mowr import db


class Analysis(db.Model):
    __tablename__ = 'analysis'
    type = db.Column(db.String(5), primary_key=True)
    soft = db.Column(db.String(10), primary_key=True)
    sample_sha256 = db.Column(db.String(64), db.ForeignKey('sample.sha256'), primary_key=True)
    sample = db.relationship('Sample', back_populates='analyzes')
    analysis_time = db.Column(db.Float, default=0)
    result = db.Column(db.String, default='')

    @validates('analysis_time')
    def validate_analysis_time(self, key, analysis_time):
        try:
            analysis_time = float(analysis_time)
        except ValueError:
            analysis_time = 0
        return analysis_time
