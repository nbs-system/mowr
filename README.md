# MOWR
More Obvious Web-malware Repository
This web interface is a virus-total like aiming at scanning web shells/malwares/etc.

## Database
The application uses Mongodb with PyMongo

## File storage
The files are stored in a folder with their sha256 as name. To prevent their execution, the files are set to chmod(400)

