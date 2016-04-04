from flask import Flask
from flask_pymongo import PyMongo

app = Flask(__name__)

#TODO Put this in a configuration file
app.config['TMP_FOLDER'] = '/tmp/uploads'
app.config['UPLOAD_FOLDER'] = '/tmp/uploads/lulz'
app.config['PMF_BIN'] = '/home/antide/stage/php-malware-finder/php-malware-finder/phpmalwarefinder'
app.config['MAX_CONTENT_LENGTH'] = 5191680 # 5Mo

app.config['MONGO_DBNAME'] = 'mowr'

app.secret_key = '!OD}7i[I3&-1IM{)?f3_:XjghNi~Hu'

mongo = PyMongo(app)

