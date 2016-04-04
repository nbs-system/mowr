from flask import Flask
from flask_pymongo import PyMongo
import base64
import os

def create_app(config_filename=''):
    app = Flask(__name__)
    app.config.from_pyfile(config_filename)
    app.config['SECRET_KEY'] = base64.b64encode(os.urandom(128))
    app.mongo = PyMongo(app)

    from mowr.views import default
    app.register_blueprint(default.default)

    return app