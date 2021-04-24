import flask
from flask import render_template, redirect, url_for, request, g
from icecream import ic
import sqlite3
from datetime import datetime as dt
import os

app = flask.Flask(__name__)
app_info = {
    'db_file': "data/changelog.db"
}

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

    prog_dict = {
        'program': 1,
        'name': 'Program 1',
        'tab0': 'active',
        'tab1': '',
    }
    if 'pr' in request.args and int(request.args['pr']) == 2:
        prog_dict['program'] = int(request.args['pr'])
        prog_dict['name'] = "Program 2"
        prog_dict['tab0'] = ''
        prog_dict['tab1'] = 'active'

    db = get_db()
    # Get versions
    _sql = " select * from version"
    cur = db.execute(_sql)
    versions = cur.fetchall()

    return render_template('base.html', pr=prog_dict, versions=versions)

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

    # Added form to db
    sql_command = "insert into features(id_version, date, description, id_author, link, title) values (?, ?, ?, ?, ?, ?);"
    db.execute(sql_command, [id_version, dt.now().strftime('%Y-%m-%d'), request.form['desc'], 1, request.form['link'], request.form['title']])
    db.commit()

    return redirect(url_for('index', pr=[f'{prog}']))
if __name__ == '__main__':
    app.run()
