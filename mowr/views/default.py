import datetime
from hashlib import sha256
from os import chmod

from flask import render_template, request, redirect, abort, url_for, flash, Blueprint, current_app, session

from mowr import db
from mowr.analyzers.analyser import Analyser
from mowr.models.sample import Sample
from mowr.models.tag import Tag
from mowr.views.common import search

default = Blueprint('default', __name__, static_folder='../static', static_url_path='/static')


@default.route('/upload', methods=['POST'])
def upload():
    """ Upload form """
    # Check file param
    file = request.files.get('file')
    if file is None or not file.filename:
        flash('Please select a valid file.', 'warning')
        return redirect(url_for('default.index'))

    analysis_type = request.form.get('type')
    if analysis_type is None or analysis_type not in current_app.config.get('FILE_TYPES'):
        flash('Sorry but the request you sent is invalid.', 'warning')
        return redirect(url_for('default.index'))

    # Check size (I think Flask is doing this by itself, but we never know...)
    if request.content_length >= current_app.config['MAX_CONTENT_LENGTH']:
        abort(413)

    # Check the file sha256 and if it has already been analysed
    file_content = file.stream.read()
    sha256sum = sha256(file_content).hexdigest()

    # If already exists ask what to do
    if sample_exists(analysis_type=analysis_type, sha256=sha256sum) == "OK":
        return redirect(url_for('default.choose', sha256=sha256sum, analysis_type=analysis_type))

    newfile = Sample.get_file_path(sha256sum)  # If it is the first time, save the file to the correct location
    file.stream.seek(0)  # Seek is needed because of the above file.stream.read()
    try:
        file.save(newfile)
    except OSError:
        flash('The file could not be saved.', 'danger')

    # Chmod the file to prevent it from being executed
    chmod(newfile, 0o400)

    # Then analyse it and show results
    analyser = Analyser(sha256=sha256sum, name=file.filename, analysis_type=analysis_type)
    if analyser.analyse():
        return redirect(url_for('default.analysis', sha256=sha256sum, analysis_type=analysis_type))
    else:
        return redirect(url_for('default.index'))


@default.route('/choose/<analysis_type>/<sha256>', methods=['GET', 'POST'])
def choose(analysis_type, sha256):
    """ Choose page """
    # Save filename
    Analyser.add_name(sha256, request.form.get("filename"))
    return render_template('choose.html', sha256=sha256, analysis_type=analysis_type)


@default.route('/analysis/<analysis_type>/<sha256>')
def analysis(analysis_type, sha256):
    """ Analysis result page """
    if analysis_type not in current_app.config.get('FILE_TYPES'):
        # TODO Get most relevant analysis to show
        return redirect(
            url_for('default.analysis', sha256=sha256, analysis_type=current_app.config.get('FILE_TYPES')[0]))
    sample = Sample.query.filter_by(sha256=sha256).first()
    if sample is None:
        abort(404)

    suggest_reanalyse = datetime.datetime.utcnow() - sample.last_analysis > datetime.timedelta(days=90)
    return render_template('analysis.html', sample=sample, analysis_type=analysis_type,
                           tag_list=Tag.get_all(), reanalyse=suggest_reanalyse)


@default.route('/analyse/<analysis_type>/<sha256>', methods=['GET', 'POST'])
def analyse(analysis_type, sha256):
    """ Reanalyse a sample """
    # TODO we should check for spamming users
    Analyser(sha256=sha256, analysis_type=analysis_type, analyse=True)
    return redirect(url_for('default.analysis', sha256=sha256, analysis_type=analysis_type))


@default.route('/login', methods=['GET', 'POST'])
def login():
    """ Logs the user in """
    if 'login' in session:
        return redirect(url_for('admin.index'))

    if request.method == 'POST':
        # Check input
        # TODO side channel ?
        if request.form.get('password') == current_app.config['ADMIN_PASSWORD']:
            if request.form.get('login') == current_app.config['ADMIN_LOGIN']:
                session['login'] = request.form.get('login')
                return redirect(url_for('admin.index'))
        else:
            flash('Sorry, are you sure about what you are doing ?', 'danger')

    return render_template('admin/login.html')


@default.route('/documentation')
def documentation():
    """ Documentation page """
    return render_template('documentation.html')


@default.route('/search', defaults={'page': 1}, methods=['GET', 'POST'])
@default.route('/search/<page>', methods=['GET', 'POST'])
def search_page(page):
    """ Search page """
    if page != 1:
        try:
            page = int(page[:10])
        except ValueError:
            page = -1
    query = request.form.get('search') or ''
    samples = search(query, page)
    return render_template('search.html', samples=samples)


@default.route('/sample/<analysis_type>/<sha256>')
def sample_exists(analysis_type, sha256):
    """ Returns OK if the file has already been analysed """
    sample = Sample.get(sha256)
    if sample is not None:
        for analysis in sample.analyzes:
            if analysis.type == analysis_type:
                return "OK"
    return "NOK"


@default.route('/tag/submit/<sha256>/<tag>')
def submit_tag(sha256, tag):
    tags = Tag.get_all()
    tag_names = [t.name for t in tags]
    if tag is None or tag not in tag_names:
        return "NOK"
    sample = Sample.get(sha256)
    sample_tag_names = [t.name for t in sample.tags]
    if sample is None or tag in sample_tag_names:
        return "NOK"

    tag = tag_names.index(tag)
    tag = tags[tag]
    sample.tags.append(tag)
    db.session.commit()
    return "OK"


@default.route('/vote/<sha256>/<mode>')
def vote(sha256, mode):
    if session.get('can_vote') == sha256:
        session.pop('can_vote', None)
        if mode == 'clean':
            sample = Sample.query.filter_by(sha256=sha256).first()
            sample.vote_clean += 1
            db.session.commit()
            return "OK"
        elif mode == 'malicious':
            sample = Sample.query.filter_by(sha256=sha256).first()
            sample.vote_malicious += 1
            db.session.commit()
            return "OK"
    return "NOK"


@default.route('/')
def index():
    return render_template('index.html', file_types=current_app.config.get('FILE_TYPES'))
