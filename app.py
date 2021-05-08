from flask import Flask, render_template, flash, redirect, url_for, request, g, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime as dt
from icecream import ic
import random
import string
import hashlib
import binascii
import sqlite3
import os

app = Flask(__name__)
app.config.from_pyfile('config.cfg')

app_info = {
    'db_file': "data/changelog.db"
}
DB = SQLAlchemy(app)


class Users(DB.Model):
    id = DB.Column(DB.Integer, primary_key=True, autoincrement=True)
    name = DB.Column(DB.String(100), nullable=False, unique=True)
    email = DB.Column(DB.String(100), nullable=False, unique=True)
    password = DB.Column(DB.Text)
    is_active = DB.Column(DB.Boolean)
    is_admin = DB.Column(DB.Boolean)


class Author(DB.Model):
    id_author = DB.Column(DB.Integer, primary_key=True, autoincrement=True)
    initial = DB.Column(DB.String(3))

    def __repr__(self):
        return "ID: {}/{}".format(self.id_author, self.initial)


class Features(DB.Model):  # parent
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


class UserPass:

    def __init__(self, user="", password=""):
        self.user = user
        self.password = password

    def hash_password(self):
        """ Hash a password for string """
        os_urandom_static = b'D\xf5\xcd\xce[\xbf\x8a\xed<k\xc7\\\xfc\x8c\x17#\x11e2i\x97\x9d\x0b\x02\x1dvAJ\xa9\xff>\xd2\xe3L\xcc\x17\xe39[\xa1\xdf 7\xda*C\xde\x93\xc6[S\x13\xe5\xde\x01\xe26\xcaL\xbf'
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac("sha512", self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(self, stored_password, provided_password):
        """ Verify a stored password against one provided by user """
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_password(self):
        random_user = "".join(random.choice(string.ascii_lowercase) for i in range(4))
        self.user = random_user

        password_characters = string.ascii_letters
        random_password = "".join(random.choice(password_characters) for i in range(4))
        self.password = random_password

    def login_user(self):
        db = get_db()
        sql_statement = 'select id, name, email, password, is_active, is_admin from users where name=?'
        cur = db.execute(sql_statement, [self.user])
        user_record = cur.fetchone()

        if user_record is not None and self.verify_password(user_record['password'], self.password):
            return user_record
        else:
            self.user = None
            self.password = None
            return None


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


@app.route('/init_app')
def init_app():
    db = get_db()
    sql_statement = 'select count(*) as cnt from users where is_active and is_admin;'
    cur = db.execute(sql_statement)
    active_admins = cur.fetchone()

    if active_admins is not None and active_admins['cnt'] > 0:
        print("Application is already set-up. Nothing to do.")
        return redirect(url_for("index"))

    # if not - create or update random admin accounts
    user_pass = UserPass()
    user_pass.get_random_user_password()
    db.execute("""insert into users(name, email, password, is_active, is_admin) values(?,?,?, True, True);""",
               [user_pass.user, 'pjot@mail.no', user_pass.hash_password()])
    db.commit()
    print("User {} with password {} has been created.".format(user_pass, user_pass.password))
    return redirect(url_for('index'))


@app.route('/features')
def features():
    if 'pr' in request.args and int(request.args['pr']) == 2:
        prog = 2
    else:
        prog = 1
    DB.create_all()
    # program = Software.query.filter(Software.id_software == prog).first()
    all_version = Version.query.all()
    distinct_versions = DB.session.query(Features.id_version).filter(Features.id_soft == prog).order_by(
        Features.id_version.desc()).distinct().all()
    content = []
    for i in range(len(distinct_versions)):
        content.append(DB.session.query(Features).filter(Features.id_version == distinct_versions[i][0]).all())

    return render_template('features.html', pr=prog, content=content, versions=all_version, ds_ver=distinct_versions, active_menu='features')


@app.route("/", methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        return render_template('login_page.html', active_menu='login')
    else:
        user_name = "" if "user_name" not in request.form else request.form['user_name']
        user_pass = "" if "user_pass" not in request.form else request.form['user_pass']

        print("user_name: ", user_name)
        print("user_pass: ", user_pass)
        login = UserPass(user_name, user_pass)
        login_record = login.login_user()

        if login_record != None:
            session['user'] = user_name
            flash("Login {} succesfull".format(user_name), category='message')
            return redirect(url_for('features'))
        else:
            flash("Login field, try again.", category='error')
            return render_template('login_page.html')


@app.route('/logout')
def logout():
    print("Session:\n", session, "\n---")
    if 'user' in session:
        session.pop('user', None)
        print('You are logged out')
    return redirect(url_for('login'))


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
    db.execute(sql_command, [id_version, dt.now().strftime('%Y-%m-%d'), request.form['desc'], 1, request.form['link'],
                             request.form['title'], prog])
    db.commit()

    return redirect(url_for('index', pr=[f'{prog}']))


@app.route('/users')
def users():
    db = get_db()
    sql_command = 'select id, name, email, is_admin, is_active from users;'
    cur = db.execute(sql_command)
    all_users = cur.fetchall()

    return render_template('users.html', active_menu="users", users=all_users)

@app.route('/user_status_change/<action>/<user_name>')
def user_status_change(action, user_name):
    return "Change is_active or is_admin for particular user."


@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
def edit_user(user_name):
    return "Edit user"


@app.route('/user_delete/<user_name>')
def delete_user(user_name):

    if 'user' not in session:
        return redirect(url_for('login'))
    login = session['user']

    db = get_db()
    sql_command = 'delete from users where name = ? and name <> ?'
    db.execute(sql_command, [user_name, login])
    db.commit()
    return redirect(url_for('users'))


@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    if "user" not in session:
        return redirect(url_for('login'))
    login = session['user']
    db = get_db()
    message = None
    user = {}
    if request.method == "GET":
        return render_template('new_user.html', active_menu='users', user=user)
    else:
        user['user_name'] = "" if 'user_name' not in request.form else request.form['user_name']
        user['email'] = "" if 'email' not in request.form else request.form['email']
        user['user_pass'] = "" if 'user_pass' not in request.form else request.form['user_pass']

        # checks if name exists in database
        cursor = db.execute('select count(*) as cnt from users where name=?', [user['user_name']])
        record = cursor.fetchone()
        is_user_name_unique = (record['cnt'] == 0)

        # checks if email exists in database
        cursor = db.execute('select count(*) as cnt from users where email=?', [user['email']])
        record = cursor.fetchone()
        is_user_email_unique = (record['cnt'] == 0)

        if user['user_name'] == '' or user['email'] == "" or user['user_pass'] == "":
            message = ("Cannot be empty", 'info')
        elif not is_user_name_unique:
            message = ("User with the name '{}' already exists.".format(user['user_name']), 'info')
        elif not is_user_email_unique:
            message = ("User with the email '{}' already exists.".format(user['email']), 'info')

        if not message:
            user_pass = UserPass(user['user_name'], user['user_pass'])
            password_hash = user_pass.hash_password()
            sql_statement = """insert into users(name, email, password, is_active, is_admin) values(?, ?, ?, True, False);"""
            db.execute(sql_statement, [user['user_name'], user['email'], password_hash])
            db.commit()
            flash("User '{}' created.".format(user['user_name']))
            return redirect(url_for('users'))
        else:
            flash("Correct error: {}".format(message[0]), category="{}".format(message[1]))
            return render_template('new_user.html', active_menu='users', user=user)


if __name__ == '__main__':
    app.run()
