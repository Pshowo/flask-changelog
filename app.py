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

    # sql_command_0 = f"select id_version, major_ver, minor_ver, sub_ver from version " \
    #               f"where id_soft == {id_soft[0]} AND major_ver=={request.form['majorVer']} " \
    #               f"and minor_ver=={request.form['minorVer']} AND sub_ver=={request.form['subVer']};"

    sql_command = "insert into version(id_soft, major_ver, minor_ver, sub_ver) values(?,?,?,?);"
    db.execute(sql_command, [id_soft[0], request.form['majorVer'], request.form['minorVer'], request.form['subVer']])
    db.commit()
    # cur = db.execute(sql_command_0)
    # id_version = cur.fetchone()
    # ic(id_version)


    form_data = {
        'version': 0,
        'date': dt.now().strftime('%Y-%m-%d'),
        'description': request.form['desc'],
        'id_author': 0,
        'link': request.form['link'],
        'title': request.form['title'],

    }

    # Added form to db
    sql_command = "insert into features(id_version, date, description, id_author, link, title) values (?, ?, ?, ?, ?, ?);"
    db.execute(sql_command, [form_data['version'], form_data['date'], form_data['description'], form_data['id_author'], form_data['link'], form_data['title']])
    db.commit()

    return redirect(url_for('index'))
if __name__ == '__main__':
    app.run()
