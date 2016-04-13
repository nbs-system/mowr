from flask import render_template, Blueprint, current_app, session, redirect, url_for, request, flash, abort
from mowr.model.db import Sample
from datetime import datetime
import six
import os

admin = Blueprint('admin', __name__, url_prefix='/admin', static_folder='../static_admin', static_url_path='/static')


@admin.route('/')
def index():
    """ Index page with statistics """
    if 'login' not in session:
        return redirect(url_for('admin.login'))
    elif session.get('login') == current_app.config['ADMIN_LOGIN']:
        return render_template('admin/index.html', stats=getstats())
    abort(404)


@admin.route('/login', methods=['GET', 'POST'])
def login():
    """ Logs the user in """
    if 'login' in session:
        return redirect(url_for('admin.index'))

    if request.method == 'POST':
        # Check input
        if request.form.get('password') == current_app.config['ADMIN_PASSWORD']:
            if request.form.get('login') == current_app.config['ADMIN_LOGIN']:
                session['login'] = request.form.get('login')
                return redirect(url_for('admin.index'))
        else:
            flash('Sorry, are you sure about what you are doing ?', 'danger')

    return render_template('admin/login.html')


@admin.route('/logout')
def logout():
    session.pop('login', None)
    return redirect(url_for('default.index'))


@admin.route('/samples', methods=['GET', 'POST'])
def samples():
    """ Samples page """
    if 'login' not in session:
        return redirect(url_for('admin.login'))
    elif session.get('login') == current_app.config['ADMIN_LOGIN']:
        s = search(request.form.get('search'))
        return render_template('admin/samples.html', search=s)
    abort(404)


@admin.route('/search/<query>/<formated>')
def searchpage(query, formated=None):
    """ API for searching (ajax) """
    if 'login' not in session:
        abort(404)
    s = search(query)
    if formated is not None:
        return render_template('admin/search_result.html', search=s)
    return str(s)


def getstats():
    """ Returns a dict containing statistics """
    ## Samples infos
    # Count samples in the database
    samplesNb = Sample.objects.count()
    # Get clean and malicious files
    clean = Sample.objects(vote_clean__gte=1).count() #TODO
    malicious = samplesNb - clean
    # Get average time
    # TODO
    #average_time = Sample.objects.average('analysis_time')
    average_time = 0.001234
    average_time *= 1000 # To milliseconds
    average_time = '%.3f' % average_time # Truncate

    samples = dict(
        nb=samplesNb,
        clean=clean,
        malicious=malicious,
        average_time=average_time
    )

    ## Disk usage
    # Count the samples size
    file_size = sum(os.path.getsize('{0}/{1}'.format(current_app.config['UPLOAD_FOLDER'], f)) for f in
                    os.listdir(current_app.config['UPLOAD_FOLDER']))
    st = os.statvfs(current_app.config.get('UPLOAD_FOLDER'))
    # Compute free space
    remaining_storage = st.f_bavail * st.f_frsize

    diskUsage = dict(
        file_size=file_size,
        remaining_storage=remaining_storage
    )

    ## Graph 1
    # Last 7 days dates from oldest to newest
    if six.PY2:
        dateList = list(reversed(
            [datetime.fromtimestamp((datetime.utcnow() - datetime.fromtimestamp(0)).total_seconds() - 3600 * 24 * i) for
             i in range(7)]))
    else:
        dateList = list(
            reversed([datetime.fromtimestamp(datetime.utcnow().timestamp() - 3600 * 24 * i) for i in range(7)]))
    dateList = [i.replace(minute=0, hour=0, second=0, microsecond=0) for i in dateList]
    # Count the samples
    data1 = [Sample.objects(first_analysis__gte=dateList[i], first_analysis__lt=dateList[i + 1]).count() for i in
             range(len(dateList) - 1)]
    data1.append(Sample.objects(first_analysis__gte=dateList[len(dateList) - 1]).count())

    samplesChart = dict(
        # Get only the year-day-month
        dateList=[i.date().isoformat() for i in dateList],
        data1=data1,
        data2=[0] * 7
    )

    ## File types
    # Get mime types from database
    rates = Sample.objects.item_frequencies('mime')
    stats = [v for i, v in rates.items()]
    if six.PY2:
        types = [i.encode('utf-8') for i in rates]
    else:
        types = [i for i in rates]

    fileType = dict(
        stats=stats,
        types=types
    )

    return dict(
        samples=samples,
        samplesChart=samplesChart,
        diskUsage=diskUsage,
        fileType=fileType
    )


def search(query):
    """ Search for a sample matching query """
    if query is None:
        return ''
    samples = Sample.objects(sha256__icontains=query)
    if not samples:
        samples = Sample.objects(name__icontains=query)
    if not samples:
        return ''
    return [samp for samp in samples]
