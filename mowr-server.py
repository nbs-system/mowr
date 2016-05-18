#!/usr/bin/env python

import os
import logging

from mowr import create_app


def __get_config_file():
    return os.path.join(os.path.dirname(os.path.abspath(__name__)), 'config.cfg')


def run(host, port):
    """ Run the app normally """
    app = create_app(__get_config_file())
    app.threaded = True
    app.debug = False

    # Avoid creating a new key each time a file is modified
    if app.debug:
        logging.warning("==============================================")
        logging.warning(
            "The application is running with debugging enabled. Please deactivate it if it's not needed !")
        logging.warning("==============================================")
        app.config[
            'SECRET_KEY'] = 'rZy9tp8G8EvtBap2cE1ibzUfhaNNJXS76InlXfcME1clVQYek5jl6hS8+TRWleAgoZGjXEKCHCPh2idlTLGsE9lIas2fa5DCNNo1UvGkKKpeUJqQ+/f9nYvLUMeaJkShV5j/GsTCa8ygNLd/Yn7DUyp2PbijNi/kqwUS9THRIWE='
    app.run(host=host, port=port)


if __name__ == '__main__':
    run(host='0.0.0.0', port=5000)
