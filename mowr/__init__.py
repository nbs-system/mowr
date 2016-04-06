from flask import Flask
from flask_mongoengine import MongoEngine
import base64
import os


def create_app(config_filename=''):
    app = Flask(__name__)
    app.config.from_pyfile(config_filename)
    app.config['SECRET_KEY'] = base64.b64encode(os.urandom(128))

    # Create database connection object
    app.db = MongoEngine(app)

    # Check PMF Path
    pmf_default_path = 'php-malware-finder/php-malware-finder/phpmalwarefinder'
    if os.access(pmf_default_path, os.R_OK):
        app.config['PMF_BIN'] = pmf_default_path
    elif not os.access(app.config['PMF_BIN'], os.R_OK):
        print("Cannot access PMF binary. Please clone the repository in the root folder or update the configuration (PMF_BIN).")
        exit(1)

    # Check upload folder access
    if not os.access(app.config['UPLOAD_FOLDER'], os.W_OK):
        try:
            os.mkdir(app.config['UPLOAD_FOLDER'])
        except:
            print("%s is not writable. Please update the configuration (UPLOAD_FOLDER)." % app.config['UPLOAD_FOLDER'])
            exit(1)

    from mowr.views import default
    from mowr.views import admin
    app.register_blueprint(default.default)
    app.register_blueprint(admin.admin)

    return app