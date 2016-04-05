from hashlib import sha256
from flask import render_template, request, redirect, abort, url_for, flash, Blueprint, current_app
from mowr.model.analyser import Analyser
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
    f = current_app.mongo.db.files.find_one({"sha256": sha256sum})

    # If already exists ask what to do
    if f is not None:
        id = f["_id"]
        return redirect(url_for('default.file', id=id, action='choose'))

    # If it is the first time, save the file to the correct location
    newfile = Analyser.getFilePath(sha256sum)
    # Seek is needed because of the above file.stream.read()
    file.stream.seek(0)
    file.save(newfile)
    # Chmod the file to prevent it from being executed
    chmod(newfile, 0o400)

    # Then analyse it and show results
    analyser = Analyser(newfile, filename=file.filename)
    id = analyser.analyse()
    return redirect(url_for('default.file', id=id, action='analysis'))


@default.route('/file/<sha>')
def checkfile(sha):
    """ Returns the id of the file's sha256 """
    f = current_app.mongo.db.files.find_one({"sha256": sha})
    if f is not None:
        return str(f["_id"])
    else:
        return "NOK"

@default.route('/file/<id>/<action>', methods=['GET', 'POST'])
def file(id, action):
    # Init analyser to check the id
    analyser = Analyser(None, id)

    # Handle action
    if action == 'choose' and request.method == 'POST':
        # Save filename
        analyser.addName(request.form["filename"])
        return render_template('choose.html', id=id)
    elif action == 'analysis':
        f = analyser.getInfos()
        return render_template('result.html', file=f, formatTag=formatTag)
    elif action == 'reanalyse':
        analyser.analyse()
        f = analyser.getInfos()
        return render_template('result.html', file=f, formatTag=formatTag)
    abort(404)

@default.route('/tag/<soft>/<tag>')
def tag(soft, tag):
    if soft == 'pmf':
        l = current_app.mongo.db.files.find({"pmf_analysis": {"$regex": ".*" + tag + ".*"}}).limit(10)
        return render_template('tag.html', files=l, formatTag=formatTag)
    else:
        abort(404)

@default.route('/')
def index():
    return render_template('index.html')

# Error handlers
@default.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

#@default.errorhandler(500)
#def page_not_found(e):
#    return render_template('500.html'), 500
