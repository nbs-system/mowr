from flask import Flask
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config['TMP_FOLDER'] = '/tmp/uploads'
app.config['UPLOAD_FOLDER'] = '/tmp/uploads/lulz'
app.config['MONGO_DBNAME'] = 'mowr'
mongo = PyMongo(app)

