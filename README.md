# crypto_app

Create a virtual environment inside a folder

Activate this virtual environment (env\scripts\activate.bat)

Install the requirements.txt file to install all the dependencies pip install -r requirements.txt

Run the project python manage.py runserver

Goto the local server url in browser e.g. http://127.0.0.1:8000

List all addresses API:
GET
http://127.0.0.1:8000/crypto/address/

Retrieve an address API:
GET
http://127.0.0.1:8000/crypto/address/<id>/

Create an address API:
POST
http://127.0.0.1:8000/crypto/address/
