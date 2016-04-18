from flask import render_template, Blueprint, current_app, session, redirect, url_for, request, flash, abort
from mowr.model.db import Sample
from mowr.model.analyser import Analyser
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
    """ Log the user out """
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


@admin.route('/delete/<sha256>')
def delete(sha256):
    """ Delete a sample from harddrive and database """
    if 'login' not in session:
        return redirect(url_for('admin.login'))
    elif session.get('login') == current_app.config['ADMIN_LOGIN'] and search(sha256):
        Sample.objects(sha256=sha256).first().delete()
        os.remove(Analyser.getfilepath(sha256))
        flash('The file %s has been deleted. Are you happy now ?' % sha256, 'warning')
        return redirect(url_for('admin.samples'))
    abort(404)


@admin.route('/edit/<sha256>', methods=['GET', 'POST'])
def edit(sha256):
    """ Edit a sample metadata """
    if 'login' not in session:
        return redirect(url_for('admin.login'))
    elif session.get('login') == current_app.config['ADMIN_LOGIN'] and search(sha256):
        sample = Sample.objects(sha256=sha256).first()
        if request.method == 'POST':
            # Reformat what is needed
            name = request.form.get('name').replace(' ', '').split(',')
            mime = request.form.get('mime')
            first_analysis = request.form.get('first_analysis')
            last_analysis = request.form.get('last_analysis')
            tags = request.form.get('tags').replace(' ', '').split(',')
            analyzes = []
            for analysis in sample.analyzes:
                analysis.time = request.form.get(analysis.type + '_analysis_time').replace(' ', '')
                analysis.pmf_result = request.form.get(analysis.type + '_pmf_result').replace(' ', '').split(',')
                analyzes.append(analysis)

            # Check inputs
            for tag in tags:
                if tag not in current_app.config.get('TAG_LIST'):
                    flash('The tag %s is not in the allowed tags list.' % tag, 'error')
                    return redirect(url_for('admin.edit', sha256=sha256))

            # Update
            sample.update(
                name=name,
                mime=mime,
                first_analysis=first_analysis,
                last_analysis=last_analysis,
                analyzes=analyzes
            )
            return redirect(url_for('admin.samples'))
        # Format name, tags and analysis before rendering
        sample.name = ', '.join([name for name in sample.name])
        sample.tags = ', '.join([tag for tag in sample.tags])
        for analysis in sample.analyzes:
            analysis.pmf_result = ', '.join([res for res in analysis.pmf_result])
        return render_template('admin/edit.html', sample=sample)
    abort(404)


def getstats():
    """ Returns a dict containing statistics """
    # Samples infos
    # Count samples in the database
    samplesNb = Sample.objects.count()
    # Get clean and malicious files
    clean = Sample.objects(vote_clean__gte=1).count()  # TODO
    malicious = samplesNb - clean
    # Get average time
    # TODO
    average_time = Sample.objects.average('analyzes.analysis_time')
    average_time *= 1000  # To milliseconds
    average_time = '%.3f' % average_time  # Truncate

    samples = dict(
        nb=samplesNb,
        clean=clean,
        malicious=malicious,
        average_time=average_time
    )

    # Disk usage
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

    # Graph 1
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

    # File types
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
