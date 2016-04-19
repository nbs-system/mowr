from flask import Blueprint, render_template, request, url_for
from mowr.model.db import Sample
from datetime import timedelta
import dateutil.parser
import shlex
import re

common = Blueprint('common', __name__, url_prefix='/common', static_folder='../static', static_url_path='/static')


@common.route('/search/<query>/<formated>')
def search_page(query, formated=None):
    """ API for searching (ajax) """
    # TODO Pagination
    s = search(query)
    if formated is not None:
        referer = '/' + re.sub(request.host_url, '', request.referrer)
        if referer == url_for('admin.samples'):
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
    # Check if prefix are used (Waoh so dirty)
    prefix_list = ['name', 'md5', 'sha1', 'sha256', 'first_analysis', 'last_analysis', 'tags']
    if ' ' in query:
        elems = [elem for elem in shlex.split(query)]
        prefixes = []
        for i, elem in enumerate(elems):
            if i % 2 == 0 and elem in prefix_list:
                prefixes.append(elem)

        req = dict()
        for prefix in prefixes:
            try:
                prefix_value = elems[elems.index(prefix) + 1]
            except IndexError:
                continue
            if prefix in ['first_analysis', 'last_analysis']:
                date = dateutil.parser.parse(prefix_value)
                n = '{prefix}__gte'.format(prefix=prefix)
                req[n] = date
                date += timedelta(days=1)
                n = '{prefix}__lt'.format(prefix=prefix)
                req[n] = date
            else:
                n = '{prefix}__icontains'.format(prefix=prefix)
                req[n] = prefix_value
        samples = Sample.objects.filter(**req)
    else:
        samples = Sample.objects(sha256__icontains=query)

    if not samples:
        samples = Sample.objects(name__icontains=query)
    if not samples:
        return ''
    return [samp for samp in samples]
