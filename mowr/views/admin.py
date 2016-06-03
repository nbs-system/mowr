import collections
import datetime
import os

import six
from flask import render_template, Blueprint, current_app, session, redirect, url_for, request, flash, abort
from werkzeug.utils import secure_filename

from mowr.lib.analyzers.archiveanalyser import ArchiveAnalyser
from mowr.lib.common import search
from mowr import db
from mowr.models.analysis import Analysis
from mowr.models.sample import Sample
from mowr.models.tag import Tag

admin = Blueprint('admin', __name__, url_prefix='/admin')


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
    samples = search(request.form.get('search', ''), page)
    return render_template('admin/samples.html', samples=samples)


@admin.route('/whitelist', methods=['GET', 'POST'])
def whitelist():
    if request.method == 'POST':
        myfile = request.files.get('file')
        if myfile is None or not myfile.filename:
            flash('Please select a valid file.', 'warning')
            return redirect(url_for('admin.whitelist'))

        # Save the file and unzip it
        saveloc = os.path.join(current_app.config.get('UPLOAD_FOLDER'), secure_filename(myfile.filename))
        try:
            myfile.save(saveloc)
        except OSError:
            flash('Error while saving the file. Aborting.', 'error')

        zipfile = ArchiveAnalyser(saveloc, request.form.get('type', 'PHP'))
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
        tag = Tag(request.form.get('name', ''), request.form.get('color', ''))
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
        tag.name = request.form.get('name', '')
        tag.color = request.form.get('color', '')
        db.session.add(tag)
        db.session.commit()
        return redirect(url_for('admin.tags'))
    return render_template('admin/add_tag.html', tag=tag)


@admin.route('/delete/<sha256>')
def delete(sha256):
    """ Delete a sample from harddrive and database """
    sample = Sample.get(sha256)
    if not sample:
        abort(404)
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


@admin.route('/edit/<sha256>', methods=['GET', 'POST'])
def edit(sha256):
    """ Edit a sample metadata """
    sample = Sample.get(sha256)
    if sample:
        all_tags = Tag.get_all()
        if request.method == 'POST':  # Reformat what is needed
            tag_input = request.form.get('tags', '').replace(' ', '').split(',')

            tag_list = []
            for i, tag_name in enumerate(tag_input):
                if not tag_name:
                    continue
                if tag_name not in (tag.name for tag in all_tags):
                    flash('The tag %s is not in the allowed tags list.' % tag_name, 'error')
                    return redirect(url_for('admin.edit', sha256=sha256))
                tag_list.append(all_tags[i])

            # Update2
            sample.name = request.form.get('name', '').replace(' ', '').split(',')
            sample.mime = request.form.get('mime', '')
            sample.first_analysis = request.form.get('first_analysis', '')
            sample.last_analysis = request.form.get('last_analysis', '')
            sample.tags = tag_list
            db.session.add(sample)
            db.session.commit()
            return redirect(url_for('admin.samples'))

        return render_template('admin/edit.html', sample=sample, names=[tag.name for tag in sample.tags])
    abort(404)


def get_stats():
    """
     :return dict of dict: Various statistics
     """

    # Count samples in the database
    samples_nb = Sample.query.count()
    if not samples_nb:
        return collections.defaultdict(lambda: collections.defaultdict(int))

    # Get clean and malicious files amounts
    malicious = [analysis.sample_sha256 for analysis in Analysis.query.filter_by(result='').all()]
    clean_number = Analysis.query.filter(~Analysis.sample_sha256.in_(malicious)).count()
    malicious_number = samples_nb - clean_number
    ratio = malicious_number * 100.0 / samples_nb

    # Get average analyse time
    average_time = db.session.query(db.func.avg(Analysis.analysis_time)).first()[0]
    average_time *= 1000  # To milliseconds
    average_time = '%.3f' % average_time  # Truncate

    samples = dict(nb=samples_nb, ratio=ratio, average_time=average_time)

    # Compute the samples on-disk size
    up_folder = current_app.config.get('UPLOAD_FOLDER')
    files_size = sum(os.path.getsize(os.path.join(up_folder, f)) for f in os.listdir(up_folder)) / 2.0**30 #Get it in GB
    st = os.statvfs(up_folder)

    # Compute the remaining free space
    remaining_storage = st.f_bavail * st.f_frsize / 2.0**30 # Get it in GB

    disk_usage = dict(file_size=round(files_size,2), remaining_storage=round(remaining_storage,2))

    # Last 7 days dates from oldest to newest
    today = datetime.datetime.today().replace(minute=0, hour=0, second=0, microsecond=0)
    dateList = list()
    nb_samples_per_day = list()

    for day_num in range(6, -1, -1):
        day = today - datetime.timedelta(days=day_num)
        next_day = day + datetime.timedelta(days=1)

        nb_samples = Sample.query.filter(Sample.first_analysis >= day, Sample.first_analysis < next_day).count()
        nb_samples_per_day.append(int(nb_samples))

        dateList.append(day.date().isoformat())

    samples_chart = dict(dateList=dateList, data1=nb_samples_per_day)

    # Get mime types from database
    count = db.func.count(Sample.mime).label('nb')
    rates = db.session.query(count, Sample.mime).group_by(Sample.mime).order_by(count.desc()).all()
    stats, types = [], []
    for i, v in rates:
        stats.append(int(i))
        types.append(v.encode('utf-8') if six.PY2 else v)

    file_type = dict(stats=stats, types=types)

    return dict(samples=samples, samplesChart=samples_chart, diskUsage=disk_usage, fileType=file_type)
