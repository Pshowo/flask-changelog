import os
basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(basedir, 'changelog.db')
SQLALCHEMY_TRACK_MODIFICATIONS=False
SECRET_KEY = b'\x07\x00\xf3k\x07\x15\x03e=PJ\x17\x1en\x02X'
DEBUG=True
CACHE_TYPE="null"
