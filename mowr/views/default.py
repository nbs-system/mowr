from hashlib import sha256
from flask import render_template, request, redirect, abort, url_for, flash, Blueprint, current_app, session
from mowr.model.analyser import Analyser
from mowr.model.db import Sample
from random import choice
from os import chmod
import magic

default = Blueprint('default', __name__)


# TODO
def tagnameToColor(tag):
    return choice(['primary', 'danger', 'success', 'default', 'warning'])


def formatTag(soft, tag):
    return '<a class="label label-' + tagnameToColor(tag) + '" href="' + url_for('default.tag', soft=soft, tag=tag) + '">' + tag +'</a>'


@default.route('/upload', methods=['POST'])
def upload():
    # Check file param
    file = request.files.get('file')
    if file is None:
        flash('There was an error while uploading the file. Please try with a different file.', 'danger')
        return redirect(url_for('default.index'))

    # Check size (I think Flask is doing this by itself, but we never know...)
    if request.content_length >= current_app.config['MAX_CONTENT_LENGTH']:
        abort(413)

    # Check file mime type from file stream and not from request content
    file_content = file.stream.read()
    mime = magic.from_buffer(file_content, mime=True).decode('utf-8')
    if mime not in current_app.config['ALLOWED_MIME']:
        flash('Sorry, this file type is not allowed. Please try with another one.', 'warning')
        return redirect(url_for('default.index'))

    # Check the file sha256 and if it already exists
    sha256sum = sha256(file_content).hexdigest()
    f = Sample.objects(sha256=sha256sum).first()

    # If already exists ask what to do
    if f is not None:
        return redirect(url_for('default.file', sha256=sha256sum, action='choose'))

    # If it is the first time, save the file to the correct location
    newfile = Analyser.getfilepath(sha256sum)
    # Seek is needed because of the above file.stream.read()
    file.stream.seek(0)
    file.save(newfile)
    # Chmod the file to prevent it from being executed
    chmod(newfile, 0o400)

    # Then analyse it and show results
    analyser = Analyser(sha256=sha256sum, filename=file.filename)
    analyser.analyse()
    return redirect(url_for('default.file', sha256=sha256sum, action='analysis'))


@default.route('/file/<sha256>')
def checkfile(sha256):
    """ Returns OK if the file exists """
    if Sample.objects(sha256=sha256).first() is not None:
        return "OK"
    return "NOK"


@default.route('/file/<sha256>/<action>', methods=['GET', 'POST'])
def file(sha256, action):
    # Init analyser to check the id
    analyser = Analyser(sha256=sha256)

    # Handle action
    if action == 'choose':
        # Save filename
        analyser.addname(request.form.get("filename"))
        return render_template('choose.html', sha256=sha256)
    elif action == 'analysis':
        f = analyser.getsample()
        return render_template('result.html', file=f, formatTag=formatTag)
    elif action == 'reanalyse':
        analyser.analyse()
        f = analyser.getsample()
        return render_template('result.html', file=f, formatTag=formatTag)
    abort(404)


@default.route('/tag/<soft>/<tag>')
def tag(soft, tag):
    if soft == 'pmf':
        l = Sample.objects(pmf_analysis=tag)
        return render_template('tag.html', files=l, formatTag=formatTag)
    else:
        abort(404)


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
    return render_template('index.html')


# Error handlers
@default.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

