from flask import Flask, render_template
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
    pmf_default_path = 'php-malware-finder/php-malware-finder'
    if os.access(pmf_default_path, os.R_OK):
        app.config['PMF_PATH'] = pmf_default_path
    elif not os.access(app.config['PMF_PATH'], os.R_OK):
        print("Cannot access PMF binary. Please clone the repository in the root folder or update the configuration (PMF_PATH).")
        exit(1)

    # Check upload folder access
    if not os.access(app.config['UPLOAD_FOLDER'], os.W_OK):
        try:
            os.mkdir(app.config['UPLOAD_FOLDER'])
        except:
            print("%s is not writable. Please update the configuration (UPLOAD_FOLDER)." % app.config['UPLOAD_FOLDER'])
            exit(1)

    # Make sure the analysis types are ok
    if app.config.get('FILE_TYPES') is None or len(app.config.get('FILE_TYPES')) == 0:
        print("Analysis types seems wrong (%s). Please update your configuration (UPLOAD_FOLDER)." % app.config[
            'FILE_TYPES'])
        exit(1)

    from mowr.views import default
    from mowr.views import admin
    app.register_blueprint(default.default)
    app.register_blueprint(admin.admin)

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('error.html', num=404), 404

    @app.errorhandler(405)
    def page_not_found(e):
        return render_template('error.html', num=405), 405

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('error.html', num=500), 500

    return app
