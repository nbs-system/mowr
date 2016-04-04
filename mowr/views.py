import os
from hashlib import sha256
from shutil import move
from flask import render_template, request, redirect, abort, url_for, flash
from werkzeug.utils import secure_filename
from mowr import app, mongo
from mowr.analyser import Analyser

def errorUpload():
    flash('There was an error while uploading the file. Please try with a different file.', 'danger')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload():
    # Check file param
    file = request.files.get('file')
    if file is None:
        return errorUpload()

    # Check size (I think Flask is doing this by itself, but we never know...)
    if request.content_length >= app.config['MAX_CONTENT_LENGTH']:
        abort(413)

    # Check filename
    path = os.path.join(app.config['TMP_FOLDER'], secure_filename(file.filename))
    if os.path.isdir(path):
        return errorUpload()

    # Save the file
    file.save(path)
    file = path

    # Check the file sha256 and if it already exists
    with open(file, 'rb') as f:
        buf = f.read()
    sha256sum = sha256(buf).hexdigest()
    f = mongo.db.files.find_one({"sha256": sha256sum})

    # If already exists, delete the uploaded file and ask what to do
    if f is not None:
        id = f["_id"]
        os.remove(file)
        return redirect(url_for('file', id=id, action='choose'))

    # If it is the first time, save the file to the correct location and delete the old one
    newfile = Analyser.getFilePath(sha256sum)
    move(file, newfile)

    # Then analyse it and show results
    analyser = Analyser(newfile)
    id = analyser.analyse()
    return redirect(url_for('file', id=id, action='analysis'))


@app.route('/file/<sha>')
def checkfile(sha):
    f = mongo.db.files.find_one({"sha256": sha})
    if f is not None:
        return str(f["_id"])
    else:
        return "NOK"

@app.route('/file/<id>/<action>', methods=['GET', 'POST'])
def file(id, action):
    # Init analyser to check the id
    analyser = Analyser(None, id)

    # Handle action
    if action == 'choose':
        return render_template('choose.html', id=id)
    elif action == 'analysis':
        # TODO Add tags for pmf answer (+bootstrap)
        f = analyser.getInfos()
        return render_template('result.html', file=f)
    elif action == 'reanalyse':
        analyser.analyse()
        f = analyser.getInfos()
        return render_template('result.html', file=f)
    else:
        abort(404)

@app.route('/')
def index():
    return render_template('index.html')

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500
