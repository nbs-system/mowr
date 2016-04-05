# MOWR - More Obvious Web-malware Repository
[![Build Status](https://travis-ci.com/xarkes/mowr.svg?token=9Xzgra6ppqzjTnDcac9B&branch=master)](https://travis-ci.com/xarkes/mowr/)

This web interface is a virus-total like aiming at scanning web shells/malwares/etc.

# Usage
This application uses MongoDB, if you do not already have it, please download and install it.
Also it uses [PMF](https://github.com/nbs-system/php-malware-finder) so you will need to clone it.
```
git clone https://github.com/xarkes/mowr
cd mowr
git clone https://github.com/nbs-system/php-malware-finder
python mowr-server.py
```

# Techincal choices
## Why nosql ?
This project was needing only one table without any relationships, so that's why I choosed NoSQL running with MongoDB.

## File storage
The files are stored in a folder with their sha256 as name. Doing so makes it quite easy to manage them. To prevent their execution, the files are set to chmod(400)

## Why not PhP/MySQL ?
As said above, MySQL didn't appear to be interesting for this project. Choice of Python over PhP is because PhP is ugly and sucks and I don't like it much. (Yes, value judgement)

# Screenshots
![Index page](/docs/index.png?raw=true "Index page")
![Analysis page](/docs/analysis.png?raw=true "Analysis page")

# License
COMING SOON