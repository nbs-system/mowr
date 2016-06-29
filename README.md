# MOWR - More Obvious Web-malware Repository
[![Build Status](https://travis-ci.org/nbs-system/mowr.svg?branch=master)](https://travis-ci.com/nbs-system/mowr/)

Mowr is a [virustotal]( https://www.virustotal.com/ )-like web application aiming at halping to detect malicious web files.

# Usage
## Requirements
This application uses [PostgreSQL]( http://www.postgresql.org/ ), if you do not already have it, please download and install it.
Create a database like below. Please note that the `strfuzzymatch` module from postgresql is required so you will need to add it.
```
createdb mowr
psql -d mowr -c "CREATE EXTENSION fuzzystrmatch;"
```

Also it uses [PMF](https://github.com/nbs-system/php-malware-finder), which can be cloned with the project.
Some python extensions require dev library to be build, so you will have to install it as well.

## Installation
```
git clone https://github.com/nbs-system/mowr --depth 1 --recursive
cd mowr

## The packages below are required to build some requirements
apt install gcc
apt install python-dev
apt install libffi-dev
apt install libfuzzy-dev
apt install postgresql-server-dev-9.4
apt install postgresql-contrib-9.4

pip install --user -r requirements.txt
python mowr-server.py
```

## Configuration
To configure the server, edit `config.cfg` to set the sql server port and host, the administrator login and password,
and `mowr-server.py` to edit the port the server runs on.

# Technical choices
## Why PostgreSQL ?
The project required a database to store each sample analysis. At first we used NoSQL with MongoDB which was in a first place interesting,
because we didn't need any relation between file analyzes.
But then the project requirements changed, and that's why the MOWR switched to PostgreSQL. PostgreSQL is one of the most commonly used DBMS
which is known for its powerfulness.

## File storage
The files are stored in a folder with their `sha256` as name. Doing so makes it quite easy to manage them. To prevent their execution, the files are set to `chmod(400)`.

## Why not PHP/MySQL ?
As said above, MySQL didn't appear to be an interesting choice. Python was chosen over PHP mostly because the later is slow, ugly, and sucks hard.


## Admin interface
The administration interface is using [Gentelella](https://github.com/puikinsh/gentelella) which is a nice template to quickly make a pretty
admin interface with cool statistics

# Customization
You can add another analyser quite easily since they are loaded dynamically.
Just create a new file (using lowercase) inside the `mowr/lib/analyzers/` directory and put at least this inside:
```python
import os
import time

from mowr.models.analysis import Analysis

class MynewAnalyser(Analysis):
    types = ['PHP', 'ASP'] # This analyser can handle those types of file
    path = ""

    @classmethod
    def load(cls, app):
        """ Returns True if the plugin has everything it needs """
        if os.access('/the/path/to/here/', os.R_OK):
            cls.path = '/the/path/to/here'
            return True
        elif os.access(os.path.join(app.config.get('BASE_DIR'), 'myplugin'), os.R_OK):
            cls.path = os.path.join(app.config.get('BASE_DIR'), 'myplugin')
            return True
        # Can't access anything :(
        return False

    def __init__(self, analysis_type, filename):
        self.type = analysis_type
        self.soft = 'MyNew'
        self.filename = filename
        self.analyse()

    def analyse(self):
        start = time.time()
        # Do your analysis here as you want to do it ...
        content = """Result here"""
        self.analysis_time = time.time() - start
        self.result = content
        return True
```
Be careful, the name of your class must be the same as your filename.
Now, enable your new analyser in the configuration:
```ini
ENABLED_ANALYZERS = ['PmfAnalyser', 'MynewAnalyser']
```
Again, the name here must be the same as the name of your class.
That's it, mowr will load it for any new analyzes.

# Screenshots
![Index page](/docs/index.png?raw=true "Index page")


![Analysis page](/docs/analysis.png?raw=true "Analysis page")


![Administration interface](/docs/admin.png?raw=true "Administration interface")

# [License](https://github.com/nbs-system/mowr/blob/master/LICENSE.txt)
`GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007`
