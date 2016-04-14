from hashlib import sha256
from flask import render_template, request, redirect, abort, url_for, flash, Blueprint, current_app, session
from mowr.model.analyser import Analyser
from mowr.model.db import Sample
from random import choice
from os import chmod
import datetime

default = Blueprint('default', __name__)


# TODO
def tagnameToColor(tag):
    return choice(['primary', 'danger', 'success', 'default', 'warning'])


# TODO Put it as global instead of passing it to the view
def formatTag(tag):
    return '<a class="label label-' + tagnameToColor(tag) + '" href="' + url_for('default.tag',
                                                                                 tag=tag) + '">' + tag + '</a>'


@default.route('/upload', methods=['POST'])
def upload():
    # Check file param
    file = request.files.get('file')
    if file is None:
        flash('There was an error while uploading the file. Please try with a different file.', 'danger')
        return redirect(url_for('default.index'))
    type = request.form.get('type')
    if type is None:
        flash('Sorry but the request you sent is invalid.', 'danger')
        return redirect(url_for('default.index'))

    # Check size (I think Flask is doing this by itself, but we never know...)
    if request.content_length >= current_app.config['MAX_CONTENT_LENGTH']:
        abort(413)

    # Check the file sha256 and if it has already been analysed
    file_content = file.stream.read()
    sha256sum = sha256(file_content).hexdigest()

    # If already exists ask what to do
    if sample_exists(type=type, sha256=sha256sum) == "OK":
        return redirect(url_for('default.choose', sha256=sha256sum, type=type))

    # If it is the first time, save the file to the correct location
    newfile = Analyser.getfilepath(sha256sum)
    # Seek is needed because of the above file.stream.read()
    file.stream.seek(0)
    try:
        file.save(newfile)
    except PermissionError:
        flash('The file could not be saved.', 'danger')

    # Chmod the file to prevent it from being executed
    chmod(newfile, 0o400)

    # Then analyse it and show results
    analyser = Analyser(sha256=sha256sum, filename=file.filename, type=type)
    analyser.analyse()
    return redirect(url_for('default.analysis', sha256=sha256sum, type=type))


@default.route('/choose/<type>/<sha256>', methods=['GET', 'POST'])
def choose(type, sha256):
    # Save filename
    analyser = Analyser(sha256=sha256)
    analyser.addname(request.form.get("filename"))
    return render_template('choose.html', sha256=sha256, type=type)


@default.route('/analysis/<type>/<sha256>')
def analysis(type, sha256):
    if type is None or type == 'any':
        # TODO Get most revelant analysis to show
        return redirect(url_for('default.analysis', sha256=sha256, type=current_app.config.get('FILE_TYPES')[0]))
    analyser = Analyser(sha256=sha256, type=type)
    f = analyser.getsample()
    if f is None:
        abort(404)
    diff = datetime.datetime.utcnow() - f.last_analysis
    suggest_reanalyse = diff > datetime.timedelta(days=90)
    return render_template('result.html', file=f, formatTag=formatTag, type=type,
                           tag_list=current_app.config.get('TAG_LIST'), reanalyse=suggest_reanalyse)


@default.route('/analyse/<type>/<sha256>', methods=['GET', 'POST'])
def reanalyse(type, sha256):
    analyser = Analyser(sha256=sha256, type=type)
    analyser.analyse()
    return redirect(url_for('default.analysis', sha256=sha256, type=type))


@default.route('/tag/<tag>')
def tag(tag):
    l = Sample.objects(tags=tag)
    return render_template('tag.html', files=l, formatTag=formatTag)


@default.route('/documentation')
def documentation():
    return render_template('documentation.html')


@default.route('/sample/<type>/<sha256>')
def sample_exists(type, sha256):
    """ Returns OK if the file has already been analysed """
    sample = Sample.objects(sha256=sha256).first()
    if sample is not None:
        for analysis in sample.analyzes:
            if analysis.type == type:
                return "OK"
    return "NOK"


@default.route('/tag/submit/<sha256>/<tag>')
def submit_tag(sha256, tag):
    if tag is None or tag not in current_app.config.get('TAG_LIST'):
        return "NOK"
    f = Sample.objects(sha256=sha256).first()
    if f is None or tag in f.tags:
        return "NOK"
    f.update(add_to_set__tags=tag)
    return "OK"


@default.route('/vote/<sha256>/<mode>')
def vote(sha256, mode):
    if session.get('can_vote') == sha256:
        session.pop('can_vote', None)
        if mode == 'clean':
            Sample.objects(sha256=sha256).update(inc__vote_clean=1)
            return "OK"
        elif mode == 'malicious':
            Sample.objects(sha256=sha256).update(inc__vote_malicious=1)
            return "OK"
    return "NOK"


@default.route('/')
def index():
    return render_template('index.html', file_types=current_app.config.get('FILE_TYPES'))
