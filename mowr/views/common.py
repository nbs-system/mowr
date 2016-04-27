import re
import shlex
from datetime import timedelta

import dateutil.parser
from flask import Blueprint, request, url_for, render_template

from mowr.models.sample import Sample
from mowr import db

common = Blueprint('common', __name__, url_prefix='/common', static_folder='../static', static_url_path='/static')


@common.route('/search/<query>/<formated>')
def search_page(query, formated=None):
    """ API for searching (ajax) """
    # TODO Pagination
    s = search(query)
    if formated == 'f':
        ref = request.referrer if request.referrer is not None else ''
        referrer = re.sub(request.host_url, '', ref)
        if referrer == url_for('admin.samples'):
            return render_template('admin/search_result.html', search=s)
        else:
            return render_template('search_result.html', search=s)
    return str(s)


def search(query):
    """ Search for a sample matching query """
    # TODO Pagination
    # Empty query ?
    if query is None:
        return ''
    # Check if prefix are used
    prefix_list = ['name', 'md5', 'sha1', 'sha256', 'first_analysis', 'last_analysis', 'tags']
    samples = []
    if ' ' in query:
        elems = [elem.replace(':', '') for elem in shlex.split(query)]
        prefixes = []
        for i, elem in enumerate(elems):
            if i % 2 == 0 and elem in prefix_list:
                prefixes.append(elem)

        req = []
        for prefix in prefixes:
            try:
                prefix_value = elems[elems.index(prefix) + 1]
            except IndexError:
                continue
            if prefix in ['first_analysis', 'last_analysis']:
                try:
                    date = dateutil.parser.parse(prefix_value)
                except ValueError:
                    continue
                req.append(getattr(Sample, prefix) >= date)
                date += timedelta(days=1)
                req.append(getattr(Sample, prefix) < date)
            elif prefix == 'name':
                # Search name
                subq = db.session.query(Sample.sha256, db.func.unnest(Sample.name).label('name')).subquery()
                subq2 = db.session.query(subq.c.sha256.distinct().label('sha256')).filter(
                    subq.c.name.like('%{val}%'.format(val=prefix_value))).subquery()
                samples.extend(db.session.query(Sample).join(subq2, Sample.sha256 == subq2.c.sha256).all())
            else:
                req.append(getattr(Sample, prefix).like('%{val}%'.format(val=prefix_value)))
        # TODO
        if not samples:
            samples.extend(Sample.query.filter(*req).all())
    else:
        samples.extend(Sample.query.filter(Sample.sha256.like('%{sha256}%'.format(sha256=query))).all())
        if not samples:
            # Search name
            subq = db.session.query(Sample.sha256, db.func.unnest(Sample.name).label('name')).subquery()
            subq2 = db.session.query(subq.c.sha256.distinct().label('sha256')).filter(
                subq.c.name.like('%{val}%'.format(val=query))).subquery()
            samples = db.session.query(Sample).join(subq2, Sample.sha256 == subq2.c.sha256).all()
    if not samples:
        return ''
    return [samp for samp in samples]
