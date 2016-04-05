# MOWR - More Obvious Web-malware Repository
[![Build Status](https://travis-ci.com/xarkes/mowr.svg?token=9Xzgra6ppqzjTnDcac9B&branch=master)](https://travis-ci.com/xarkes/mowr/)

Mowr is a [virustotal]( https://www.virustotal.com/ )-like web application aiming at halping to detect malicious web files.

# Usage
This application uses [MongoDB]( https://www.mongodb.org/ ), if you do not already have it, please download and install it.
Also it uses [PMF](https://github.com/nbs-system/php-malware-finder) so you will need to clone it.
```
git clone https://github.com/xarkes/mowr
cd mowr
pip install -r requirements.txt
git clone https://github.com/nbs-system/php-malware-finder
python mowr-server.py
```

# Technical choices
## Why nosql ?
The project doesn't need relational database, since it only uses one unique table in which we do various kind of different searches, hence NoSQL.

## File storage
The files are stored in a folder with their `sha256` as name. Doing so makes it quite easy to manage them. To prevent their execution, the files are set to `chmod(400)`.

## Why not php/MySQL ?
As said above, MySQL didn't appear to be an interesting choice. Python was chosen over php mostly because the later is slow, ugly, and sucks hard.

# Screenshots
![Index page](/docs/index.png?raw=true "Index page")
![Analysis page](/docs/analysis.png?raw=true "Analysis page")

# License
COMING SOON
