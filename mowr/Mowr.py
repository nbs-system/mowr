import os
from hashlib import sha256
from shutil import move

from flask import Flask, render_template, request, redirect, abort
from flask.ext.pymongo import PyMongo

import Analyser

# Configuration
app = Flask(__name__)
app.config['TMP_FOLDER'] = '/tmp/uploads'
app.config['UPLOAD_FOLDER'] = '/tmp/uploads/lulz'
mongo = PyMongo(app)

# Custom functions
def getFileLocation(sha256sum):
    return '{0}/{1}'.format(app.config['UPLOAD_FOLDER'], sha256sum)

# Routes
@app.route('/upload', methods=['POST'])
def upload():
    # Save file in temp folder
    file = request.files['file']

    #TODO check file length
    #TODO Add tags for pmf answer (+bootstrap)
    #TODO hash cote client

    # Check user input
    path = os.path.join(app.config['TMP_FOLDER'], file.filename)
    if os.path.isdir(path):
        #TODO add flash error
        return redirect('/')

    file.save(path)
    file = path

    # Check the file sha256 and if it already exists
    with open(file, 'rb') as f:
        buf = f.read()
    sha256sum = sha256(buf).hexdigest()
    f = mongo.db.files.find_one({"sha256": sha256sum})

    # If already exists, delete the old one and ask what to do
    if f is not None:
        id = f["_id"]
        os.remove(file)
        return redirect('/file/%s/choice' % id)

    # If it is the first time, save the file to the correct location and delete the old one
    newfile = getFileLocation(sha256sum)
    move(file, newfile)

    # Then analyse it and show results
    analyser = Analyser.Analyser(mongo, newfile)
    id = analyser.analyse()
    return redirect('/file/%s/analysis' % id)


@app.route('/file/<id>/<action>', methods=['GET', 'POST'])
def file(id, action):
    # Init analyser to check the id
    analyser = Analyser.Analyser(mongo, None, id)

    # Handle action
    if action == 'choice':
        return render_template('choose.html', id=id)
    elif action == 'analysis':
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

def run():
    # Check folder access
    if not os.access(app.config['TMP_FOLDER'], os.W_OK) or not os.access(app.config['UPLOAD_FOLDER'], os.W_OK):
        print("Either TMP_FOLDER or UPLOAD_FOLDER is not writable. Please update the configuration.")

    app.debug = True
    app.run()

