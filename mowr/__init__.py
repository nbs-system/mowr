import base64
import os
import logging
import importlib

from flask import Flask, render_template
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError

logging.basicConfig()
logger = logging.getLogger("mowr")
logger.setLevel(logging.INFO)

db = SQLAlchemy()


def load_analyzers(app):
    analyzers = app.config.get('ENABLED_ANALYZERS')
    for analyser in analyzers:
        try:
            mod = importlib.import_module("mowr.lib.analyzers." + analyser.lower())
            cls = getattr(mod, analyser)
            error = not cls.load(app)
        except ImportError:
            logger.warning("Could not import the module %s" % analyser)
            error = True
        if error:
            analyzers.remove(analyser)
    app.config['ENABLED_ANALYZERS'] = analyzers
    if len(analyzers) < 1:
        logger.error("There are no analyser enabled. Exiting.")
        exit(1)
    logger.info("Those modules were loaded: %s" % analyzers)


def create_app(config_filename=''):
    app = Flask(__name__)
    app.config.from_pyfile(config_filename)
    app.config['SECRET_KEY'] = base64.b64encode(os.urandom(128))

    # Set database config
    db.init_app(app)
    db.app = app

    app.config['BASE_DIR'] = os.path.dirname(os.path.dirname(__file__))
    load_analyzers(app)

    # Check upload folder access
    if not os.access(app.config['UPLOAD_FOLDER'], os.W_OK):
        try:
            os.mkdir(app.config['UPLOAD_FOLDER'])
        except OSError:
            logger.error("%s is not writable. Please update the configuration (UPLOAD_FOLDER)." % app.config['UPLOAD_FOLDER'])
            exit(1)

    # Make sure the analysis types are ok
    if app.config.get('FILE_TYPES') is None or len(app.config.get('FILE_TYPES')) == 0:
        logger.error("Analysis types seems wrong (%s). Please update your configuration (UPLOAD_FOLDER)." % app.config[
            'FILE_TYPES'])
        exit(1)

    from mowr.views import default
    from mowr.views import admin
    app.register_blueprint(default.default)
    app.register_blueprint(admin.admin)

    # Drop and create database because it's fun
    try:
        db.create_all()
    except OperationalError:
        logger.error("Could not connect to the database. Check your configuration and server settings.")
        exit(1)

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
