import os
from datetime import datetime

import six
from flask import render_template, Blueprint, current_app, session, redirect, url_for, request, flash, abort
from werkzeug.utils import secure_filename

from mowr import db
from mowr.models.analysis import Analysis
from mowr.models.sample import Sample
from mowr.views.common import search
from mowr.models.tag import Tag
from mowr.analyzers.legit import Legit

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


@admin.route('/samples', defaults={'page': 1}, methods=['GET', 'POST'])
@admin.route('/samples/<page>', methods=['GET', 'POST'])
def samples(page):
    """ Samples page """
    if 'login' not in session:
        return redirect(url_for('admin.login'))
    elif session.get('login') == current_app.config['ADMIN_LOGIN']:
        page = int(page)
        query = request.form.get('search')
        samples = search(query, page)
        return render_template('admin/samples.html', samples=samples)
    abort(404)


@admin.route('/whitelist', methods=['GET', 'POST'])
def whitelist():
    if 'login' not in session:
        return redirect(url_for('admin.login'))
    elif session.get('login') == current_app.config['ADMIN_LOGIN']:
        if request.method == 'POST':
            myfile = request.files.get('file')
            if myfile is None or not myfile.filename:
                flash('Please select a valid file.', 'warning')
                return redirect(url_for('admin.whitelist'))

            # Save the file and unzip it
            filename = secure_filename(myfile.filename)
            saveloc = os.path.join(current_app.config.get('UPLOAD_FOLDER'), filename)
            try:
                myfile.save(saveloc)
            except OSError:
                flash('Error while saving the file. Aborting.', 'error')

            analyse_type = request.form.get('type')
            zipfile = Legit(saveloc, analyse_type)
            zipfile.analyse()
            os.remove(saveloc)
        return render_template('admin/whitelist.html')
    abort(404)

@admin.route('/delete/<sha256>')
def delete(sha256):
    """ Delete a sample from harddrive and database """
    if 'login' not in session:
        return redirect(url_for('admin.login'))
    sample = Sample.get(sha256)
    if session.get('login') == current_app.config['ADMIN_LOGIN'] and sample is not None:
        for tag in sample.tags:
            db.session.delete(tag)
        for analysis in sample.analyzes:
            db.session.delete(analysis)
        db.session.delete(sample)
        db.session.commit()
        try:
            os.remove(Sample.get_file_path(sha256))
        except OSError:
            flash('Could not delete the file from the file system.', 'danger')
        flash('The file %s has been deleted. Are you happy now ?' % sha256, 'warning')
        return redirect(url_for('admin.samples'))
    abort(404)


@admin.route('/edit/<sha256>', methods=['GET', 'POST'])
def edit(sha256):
    """ Edit a sample metadata """
    if 'login' not in session:
        return redirect(url_for('admin.login'))
    sample = Sample.get(sha256)
    if session.get('login') == current_app.config['ADMIN_LOGIN'] and sample:
        if request.method == 'POST':
            # Reformat what is needed
            name = request.form.get('name').replace(' ', '').split(',')
            mime = request.form.get('mime')
            first_analysis = request.form.get('first_analysis')
            last_analysis = request.form.get('last_analysis')
            tag_input = request.form.get('tags').replace(' ', '').split(',')
            analyzes = []
            for analysis in sample.analyzes:
                analysis.analysis_time = request.form.get(analysis.type + '_analysis_time').replace(' ', '')
                analysis.result = request.form.get(analysis.type + '_pmf_result').replace(' ', '').split(',')
                analyzes.append(analysis)

            # Check inputs
            all_tags = Tag.get_all()
            available_tags = [tag.name for tag in all_tags]
            tag_list = []
            for i, tag_name in enumerate(tag_input):
                if tag_name not in available_tags:
                    flash('The tag %s is not in the allowed tags list.' % tag_name, 'error')
                    return redirect(url_for('admin.edit', sha256=sha256))
                tag_list.append(all_tags[i])

            # Update2
            sample.name = name
            sample.mime = mime,
            sample.first_analysis = first_analysis,
            sample.last_analysis = last_analysis,
            sample.analyzes = analyzes
            sample.tags = tag_list
            db.session.add(sample)
            db.session.commit()
            return redirect(url_for('admin.samples'))

        return render_template('admin/edit.html', sample=sample)
    abort(404)


def getstats():
    """ Returns a dict containing statistics """
    # Samples infos
    # Count samples in the database
    samplesNb = Sample.query.count()
    # Get clean and malicious files
    malicious = [analysis.sample_sha256 for analysis in Analysis.query.filter_by(result='').all()]
    clean_number = Analysis.query.filter(
        Analysis.result != '',
        ~Analysis.sample_sha256.in_(malicious)
    ).count()
    malicious_number = samplesNb - clean_number
    try:
        ratio = malicious_number * 100 / samplesNb
    except ZeroDivisionError:
        ratio = 0

    # Get average time
    average_time = db.session.query(db.func.avg(Analysis.analysis_time)).first()[0]
    average_time *= 1000  # To milliseconds
    average_time = '%.3f' % average_time  # Truncate

    samples = dict(
        nb=samplesNb,
        ratio=ratio,
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
    data1 = [Sample.query.filter(Sample.first_analysis >= dateList[i], Sample.first_analysis < dateList[i + 1]).count()
             for i in range(len(dateList) - 1)]
    data1.append(Sample.query.filter(Sample.first_analysis >= dateList[len(dateList) - 1]).count())

    samplesChart = dict(
        # Get only the year-day-month
        dateList=[i.date().isoformat() for i in dateList],
        data1=[int(d) for d in data1],
        data2=[0] * 7
    )

    # File types
    # Get mime types from database
    rates = db.session.query(db.func.count(Sample.mime), Sample.mime).group_by(Sample.mime).all()
    stats = []
    types = []
    for i, v in rates:
        stats.append(int(i))
        if six.PY2:
            types.append(v.encode('utf-8'))
        else:
            types.append(v)

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

