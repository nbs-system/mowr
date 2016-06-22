#!/usr/bin/env python

import os
import logging

from mowr import create_app


def __get_config_file():
    return os.path.join(os.path.dirname(os.path.abspath(__name__)), 'config.cfg')

app = create_app(__get_config_file())

if __name__ == '__main__':
    app.run(host='0.0.0.0')

