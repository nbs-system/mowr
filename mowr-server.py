#!/usr/bin/env python

from mowr import app
import os

if __name__ == '__main__':
    # Check folder access
    if not os.access(app.config['TMP_FOLDER'], os.W_OK) or not os.access(app.config['UPLOAD_FOLDER'], os.W_OK):
        print("Either TMP_FOLDER or UPLOAD_FOLDER is not writable. Please update the configuration.")
        exit(1)

    import mowr.views

    app.debug = True
    app.run()