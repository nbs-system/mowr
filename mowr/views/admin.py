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


@admin.before_request
def restrict_admin():
    if 'login' not in session:
        return redirect(url_for('default.login'))


@admin.route('/')
def index():
    """ Index page with statistics """
    return render_template('admin/index.html', stats=get_stats())


@admin.route('/logout')
def logout():
    """ Log the user out """
    session.pop('login', None)
    return redirect(url_for('default.index'))


@admin.route('/samples', defaults={'page': 1}, methods=['GET', 'POST'])
@admin.route('/samples/<int:page>', methods=['GET', 'POST'])
def samples(page):
    """ Samples page """
    query = request.form.get('search') or ''
    samples = search(query, page)
    return render_template('admin/samples.html', samples=samples)


@admin.route('/whitelist', methods=['GET', 'POST'])
def whitelist():
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
    return render_template('admin/whitelist.html', file_types=current_app.config.get('FILE_TYPES'))


@admin.route('/tags')
def tags():
    tag_list = Tag.get_all()
    return render_template('admin/tags.html', tags=tag_list)


@admin.route('/tags/add', methods=['GET', 'POST'])
def add_tag():
    if request.method == 'POST':
        name = request.form.get('name')
        color = request.form.get('color')
        tag = Tag(name, color)
        db.session.add(tag)
        db.session.commit()
        return redirect(url_for('admin.tags'))
    return render_template('admin/add_tag.html', tag=None)


@admin.route('/tags/delete/<int:tag_id>')
def delete_tag(tag_id):
    tag = Tag.get(tag_id)
    if not tag:
        abort(404)
    db.session.delete(tag)
    db.session.commit()
    return redirect(request.referrer)


@admin.route('/tags/edit/<int:tag_id>', methods=['GET', 'POST'])
def edit_tag(tag_id):
    tag = Tag.get(tag_id)
    if not tag:
        abort(404)
    elif request.method == 'POST':
        name = request.form.get('name')
        color = request.form.get('color')
        tag.name = name
        tag.color = color
        db.session.add(tag)
        db.session.commit()
        return redirect(url_for('admin.tags'))
    else:
        return render_template('admin/add_tag.html', tag=tag)


@admin.route('/delete/<sha256>')
def delete(sha256):
    """ Delete a sample from harddrive and database """
    sample = Sample.get(sha256)
    if sample:
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
        flash('The file %s has been deleted. Are you happy now ?' % sha256, 'success')
        return redirect(request.referrer)
    abort(404)


@admin.route('/edit/<sha256>', methods=['GET', 'POST'])
def edit(sha256):
    """ Edit a sample metadata """
    sample = Sample.get(sha256)
    if sample:
        all_tags = Tag.get_all()
        if request.method == 'POST':
            # Reformat what is needed
            name = request.form.get('name').replace(' ', '').split(',')
            mime = request.form.get('mime')
            first_analysis = request.form.get('first_analysis')
            last_analysis = request.form.get('last_analysis')
            tag_input = request.form.get('tags').replace(' ', '').split(',')
            analyzes = []
            for analysis in sample.analyzes:
                time = request.form.get(
                    '{type}_{soft}_analysis_time'.format(type=analysis.type, soft=analysis.soft)).replace(' ', '')
                result = request.form.get(
                    '{type}_{soft}_result'.format(type=analysis.type, soft=analysis.soft))
                analysis.analysis_time = time
                analysis.result = result
                analyzes.append(analysis)

            # Check inputs
            available_tags = [tag.name for tag in all_tags]
            tag_list = []
            for i, tag_name in enumerate(tag_input):
                if len(tag_input) == 1 and tag_input[0] == '':
                    break
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

        return render_template('admin/edit.html', sample=sample, names=[tag.name for tag in sample.tags])
    abort(404)


def get_stats():
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
    count = db.func.count(Sample.mime).label('nb')
    rates = db.session.query(count, Sample.mime).group_by(Sample.mime).order_by(count.desc()).all()
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
