# flask-changelog

Create config.py example:

	import os
	basedir = os.path.abspath(os.path.dirname(__file__))

	SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(basedir, 'changelog.db')
	SQLALCHEMY_TRACK_MODIFICATIONS=False
	SECRET_KEY = b'\x07\x00\xf3k\x07\x15\x03e=PJ\x17\x1en\x02X'
	DEBUG=True
	CACHE_TYPE="null"

## Docker
`sudo docker build . -t flaskapp`
`sudo docker run --publish 5000:5000 flaskapp`

## Fisrt run
[http://127.0.0.1:5000/init_app](http://127.0.0.1:5000/init_app)
