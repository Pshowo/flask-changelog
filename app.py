from flask import Flask, render_template, redirect, url_for, request, g
from icecream import ic
import sqlite3
from datetime import datetime as dt
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config.from_pyfile('config.cfg')

app_info = {
    'db_file': "data/changelog.db"
}
DB = SQLAlchemy(app)


class Author(DB.Model):
    id_author = DB.Column(DB.Integer, primary_key=True, autoincrement=True)
    initial = DB.Column(DB.String(3))

    def __repr__(self):
        return "ID: {}/{}".format(self.id_author, self.initial)


class Features(DB.Model):  #parent
    __tablename__ = 'features'
    id_features = DB.Column(DB.Integer, primary_key=True, autoincrement=True)
    id_version = DB.Column(DB.Integer, DB.ForeignKey('version.id_version'))
    date = DB.Column(DB.String, nullable=False)
    description = DB.Column(DB.Text)
    id_author = DB.Column(DB.Integer)
    link = DB.Column(DB.String(250))
    title = DB.Column(DB.String(200))
    id_soft = DB.Column(DB.Integer)

    versions = DB.relationship('Version', back_populates="all_version", lazy=True)
    # version_minor =
    # version_sub =

    def __repr__(self):
        return "ID: {}".format(self.id_features)


class Version(DB.Model):  # child
    id_version = DB.Column(DB.Integer, primary_key=True, autoincrement=True, )
    id_soft = DB.Column(DB.Integer)
    major_ver = DB.Column(DB.Integer)
    minor_ver = DB.Column(DB.Integer)
    sub_ver = DB.Column(DB.Integer)
    all_version = DB.relationship("Features", back_populates="versions")

    def __repr__(self):
        return "ID{}: {}/{}.{}.{}".format(self.id_soft, self.id_version, self.major_ver, self.minor_ver, self.sub_ver)


class Software(DB.Model):
    id_software = DB.Column(DB.Integer, primary_key=True, autoincrement=True)
    name = DB.Column(DB.String(30))

    def __repr__(self):
        return "ID: {}/{}".format(self.id_software, self.name)



def get_db():
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(app_info['db_file'])
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn
    return g.sqlite_db


# Close database connection when application context ends.
@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


@app.route('/')
def index():

    if 'pr' in request.args and int(request.args['pr']) == 2:
        prog = 2
    else:
        prog = 1
    DB.create_all()
    # program = Software.query.filter(Software.id_software == prog).first()
    all_version = Version.query.all()
    distinct_versions = DB.session.query(Features.id_version).filter(Features.id_soft == prog).order_by(Features.id_version.desc()).distinct().all()
    content = []
    for i in range(len(distinct_versions)):
        content.append(DB.session.query(Features).filter(Features.id_version == distinct_versions[i][0]).all())

    return render_template('base.html', pr=prog, content=content, versions=all_version, ds_ver=distinct_versions)


@app.route('/form', methods=['GET', 'POST'])
def form():

    for p in request.form:
        print(p, request.form[p])

    db = get_db()
    sql_command = f"select id_software from software where name is '{request.form['programName']}';"
    cur = db.execute(sql_command)
    id_soft = cur.fetchone()
    ic(id_soft[0])

    # ------------------------------
    if request.form['programName'] == 'Program 1':
        prog = 1
    else:
        prog = 2
    value_list = [prog, request.form['majorVer'], request.form['minorVer'], request.form['subVer']]
    # Checks if the version is available in db
    sql_command1 = f"select * from version where id_soft==? and major_ver==? and minor_ver==? and sub_ver==?;"
    cur = db.execute(sql_command1, value_list)
    id_soft = cur.fetchone()
    if id_soft is None:
        # Version non exists, create new
        sql_command = "insert into version(id_soft, major_ver, minor_ver, sub_ver) values (?, ?, ?, ?);"
        db.execute(sql_command, value_list)
        db.commit()
        cur = db.execute(sql_command1, value_list)
        id_soft = cur.fetchone()
        a = (dict(zip(id_soft.keys(), id_soft)))
        id_version = a['id_version']
    else:
        # Version is avaiable, returns id_version
        a = (dict(zip(id_soft.keys(), id_soft)))
        id_version = a['id_version']
    # -------------------------------------

    # Added form to db
    sql_command = "insert into features(id_version, date, description, id_author, link, title, id_soft) values (?, ?, ?, ?, ?, ?, ?);"
    db.execute(sql_command, [id_version, dt.now().strftime('%Y-%m-%d'), request.form['desc'], 1, request.form['link'], request.form['title'], prog])
    db.commit()

    return redirect(url_for('index', pr=[f'{prog}']))
if __name__ == '__main__':
    app.run()
