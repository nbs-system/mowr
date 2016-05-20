# MOWR - More Obvious Web-malware Repository
[![Build Status](https://travis-ci.com/xarkes/mowr.svg?token=9Xzgra6ppqzjTnDcac9B&branch=master)](https://travis-ci.com/xarkes/mowr/)

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
git clone https://github.com/xarkes/mowr --depth 1 --recursive
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
## ~~Why nosql ?~~
~~The project doesn't need relational database, since it only uses one unique table in which we do various kind of different searches, hence NoSQL.~~
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


# Screenshots
![Index page](/docs/index.png?raw=true "Index page")


![Analysis page](/docs/analysis.png?raw=true "Analysis page")


![Administration interface](/docs/admin.png?raw=true "Administration interface")

# License
COMING SOON (Right ?)
