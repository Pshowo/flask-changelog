from flask import Flask, render_template, flash, redirect, url_for, request, g, session, send_file
from flask.helpers import send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime as dt
from icecream import ic
import random
import string
import hashlib
import binascii
import sqlite3
from docxtpl import DocxTemplate
from multiprocessing import Process
import os
from icecream import ic

app = Flask(__name__)


app.config.from_pyfile('config.py')
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
    id_title = DB.Column(DB.Integer, DB.ForeignKey('title.id_title'))
    id_soft = DB.Column(DB.Integer)
    id_author = DB.Column(DB.Integer)
    description = DB.Column(DB.Text)
    date = DB.Column(DB.String, nullable=False)
    link = DB.Column(DB.String(250))

    versions = DB.relationship('Version', back_populates="all_version", lazy=True)

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
    description = DB.Column(DB.Text)

    def __repr__(self):
        return "ID: {}/{}".format(self.id_software, self.name)


class Title(DB.Model):
    id_title = DB.Column(DB.Integer, primary_key=True, autoincrement=True)
    id_software = DB.Column(DB.Integer, nullable=False)
    id_version = DB.Column(DB.Integer)
    title = DB.Column(DB.String(200))
    date = DB.Column(DB.String, nullable=False)
    features = DB.relationship('Features', backref="features", lazy=True)

    def __repr__(self):
        return "{}. {}".format(self.id_title, self.title)

class UserPass:

    def __init__(self, user="", password=""):
        self.user = user
        self.password = password
        self.email = ''
        self.is_valid = False
        self.is_admin = False

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
        user_record = Users.query.filter(Users.name == self.user).first()

        if user_record is not None and self.verify_password(user_record.password, self.password):
            if user_record.is_active:
                return user_record
            else:
                flash("Account is disable. Contact with your admin.", category='warning')
                self.user = None
                self.password = None
                return None
        else:
            self.user = None
            self.password = None
            return None

    def get_user_info(self):
        db_user = Users.query.filter_by(name=self.user).first()

        if db_user is None:
            self.is_valid = False
            self.is_admin = False
            self.email = ""
        elif db_user.is_active != 1:
            self.is_valid = False
            self.is_admin = False
            self.email = db_user.email
        else:
            self.is_valid = True
            self.is_admin = db_user.is_admin
            self.email = db_user.email


def get_db():
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(app.config['SQLALCHEMY_DATABASE_URI'])
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
    DB.create_all()
    active_admins = Users.query.filter(Users.is_active == True).filter(Users.is_admin == True).count()
    if active_admins is not None and active_admins > 0:
        flash("Application is already set-up. Nothing to do.")
        return redirect(url_for("login"))

    # if not - create or update random admin accounts
    user_pass = UserPass()
    user_pass.get_random_user_password()
    new_admin = Users(name=user_pass.user, email='pjot@mail.no', password=user_pass.hash_password(), is_active=True, is_admin=True)
    DB.session.add(new_admin)
    DB.session.commit()
    print("User {} with password {} has been created.".format(user_pass.user, user_pass.password))
    flash("User {} with password {} has been created.".format(user_pass.user, user_pass.password))
    return redirect(url_for('login'))


@app.route('/features/<int:program>')
def features(program):
    login = UserPass(session.get('user'))
    login.get_user_info()

    DB.create_all()

    all_version = Version.query.all()
    distinct_versions = DB.session.query(Features.id_version).filter(Features.id_soft == program).order_by(
        Features.id_version.desc()).distinct().all()
    content = []
    for i in range(len(distinct_versions)):
        content.append(DB.session.query(Features).filter(Features.id_version == distinct_versions[i][0]).all())
    programs = Software.query.all()  # software
    titles = DB.session.query(Title).filter(Title.id_software == program).distinct().all()
    dis_titles = DB.session.query(Title.title).filter(Title.id_software==program).distinct().all()

    return render_template('features.html', pr=program, content=content, versions=all_version, ds_ver=distinct_versions,
                           active_menu='features', login=login, programs=programs, titles=titles, options=dis_titles)


@app.route('/form', methods=['GET', 'POST'])
def form():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    program_id = int(request.form['program_id'])
    majorVer = request.form['majorVer']
    minorVer = request.form['minorVer']
    subVer = request.form['subVer']
    # Checks if version exist:
    ver_ID = Version.query.filter(Version.id_soft == program_id).\
        filter(Version.major_ver == request.form['majorVer']).\
        filter(Version.minor_ver == request.form['minorVer']).\
        filter(Version.sub_ver == request.form['subVer']).first()

    if ver_ID is None:
        # Adding new Version
        new_version = Version(id_soft=program_id, major_ver=request.form['majorVer'], minor_ver=request.form['minorVer'], sub_ver=request.form['subVer'])
        DB.session.add(new_version)
        DB.session.commit()
        ver_ID = Version.query.filter(Version.id_soft == program_id).\
            filter(Version.major_ver == request.form['majorVer']).\
            filter(Version.minor_ver == request.form['minorVer']).\
            filter(Version.sub_ver == request.form['subVer']).first()
    # Checks if the title exist:
    title_ID = Title.query.filter(Title.id_version == ver_ID.id_version).\
        filter(Title.id_software == program_id).\
        filter(Title.title == request.form['title']).first()

    if title_ID is None:
        # Adding new title
        new_title = Title(id_software=program_id, id_version=ver_ID.id_version, title=request.form['title'], date=dt.now().strftime('%Y-%m-%d'))
        DB.session.add(new_title)
        DB.session.commit()
        title_ID = Title.query.filter(Title.id_version == ver_ID.id_version).\
            filter(Title.id_software == program_id).\
            filter(Title.title == request.form['title']).first()
    # Added form to db
    new_feature = Features(id_version=ver_ID.id_version, id_title=title_ID.id_title, id_soft=program_id, id_author=1, description=request.form['desc'], date=dt.now().strftime('%Y-%m-%d'), link=request.form['link'])
    DB.session.add(new_feature)
    DB.session.commit()

    gen_file(program_id, ver_ID.id_version)

    return redirect(url_for('features', program=program_id))


@app.route("/", methods=['GET', 'POST'])
def login():
    login = UserPass(session.get('user'))
    login.get_user_info()

    if request.method == "GET":
        return render_template('login_page.html', active_menu='login', login=login)
    else:
        user_name = "" if "user_name" not in request.form else request.form['user_name']
        user_pass = "" if "user_pass" not in request.form else request.form['user_pass']

        login = UserPass(user_name, user_pass)
        login_record = login.login_user()

        if login_record != None:
            session['user'] = user_name
            flash("Login {} succesfull".format(user_name), category='message')
            first_prog = Software.query.first()
            print(" *** First prog: ", first_prog)
            if first_prog == None:
                first_prog = 0
            else:
                first_prog = first_prog.id_software
            return redirect(url_for('features', program=first_prog))
        else:
            flash("Login field, try again.", category='error')
            return render_template('login_page.html', active_menu='login', login=login)


@app.route('/logout')
def logout():

    if 'user' in session:
        session.pop('user', None)
        flash('You are logged out', category='info')
    return redirect(url_for('login'))


@app.route('/users')
def users():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    all_users = Users.query.all()

    return render_template('users.html', active_menu="users", users=all_users, login=login)


@app.route('/user_status_change/<action>/<user_name>')
def user_status_change(action, user_name):
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()

    if action == 'active':
        db.execute("""update users set is_active = (is_active + 1) % 2
                    where name =? and name <> ?;""", [user_name, login.user])
        db.commit()
    elif action == "admin":
        db.execute("""update users set is_admin = (is_admin + 1) % 2
                            where name =? and name <> ?;""", [user_name, login.user])
        db.commit()
    return redirect(url_for('users'))

@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
def edit_user(user_name):
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    user = Users.query.filter_by(name=user_name).first()

    if user is None:
        flash("No such user", category='warning')
        return redirect(url_for('users'))
    if request.method == 'GET':
        return render_template('edit_user.html', active_menu='users', user=user, login=login)
    else:
        new_email = '' if 'email' not in request.form else request.form['email']
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']

        if new_email != user.email:
            user.email = new_email
            DB.session.commit()
            flash("Email was changed", category='message')

        if new_password != '':
            user_pass = UserPass(user_name, new_password)
            user.password = user_pass.hash_password()
            DB.session.commit()
            flash("Password was changed", category='message')
        return redirect(url_for('users'))

@app.route('/user_delete/<user_name>')
def delete_user(user_name):
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    if 'user' not in session:
        return redirect(url_for('login'))
    login = session['user']

    db = get_db()

    user = Users.query.filter_by(name=user_name).first()
    if user.name == login:
        flash("Can not delete your own account.")
    else:
        flash("User {} was deleted.".format(user.name))
        DB.session.delete(user)
        DB.session.commit()

    return redirect(url_for('users'))


@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    message = None
    user = {}
    if request.method == "GET":
        return render_template('new_user.html', active_menu='users', user=user, login=login)
    else:
        user['user_name'] = "" if 'user_name' not in request.form else request.form['user_name']
        user['email'] = "" if 'email' not in request.form else request.form['email']
        user['user_pass'] = "" if 'user_pass' not in request.form else request.form['user_pass']

        # checks if name exists in database
        is_user_name_unique = (Users.query.filter_by(name=user['user_name']).count() == 0)

        # checks if email exists in database
        is_user_email_unique = (Users.query.filter_by(email=user['email']).count() == 0)

        if user['user_name'] == '' or user['email'] == "" or user['user_pass'] == "":
            message = ("Cannot be empty", 'info')
        elif not is_user_name_unique:
            message = ("User with the name '{}' already exists.".format(user['user_name']), 'info')
        elif not is_user_email_unique:
            message = ("User with the email '{}' already exists.".format(user['email']), 'info')

        if not message:
            user_pass = UserPass(user['user_name'], user['user_pass'])
            password_hash = user_pass.hash_password()
            new_user = Users(name=user['user_name'], email=user['email'], password=password_hash, is_active=True, is_admin=False)
            DB.session.add(new_user)
            DB.session.commit()
            flash("User '{}' created.".format(user['user_name']))
            return redirect(url_for('users'))
        else:
            flash("Correct error: {}".format(message[0]), category="{}".format(message[1]))
            return render_template('new_user.html', active_menu='users', user=user, login=login)

@app.route('/programs', methods=['GET','POST'])
def programs():
    login = UserPass(session.get('user'))
    login.get_user_info()
    program = {}

    softwares = Software.query.all()
    if request.method == "GET":
        return render_template('programs.html', softwares=softwares, active_menu='programs', login=login)
    else:
        program['name'] = "" if "name" not in request.form else request.form['name']
        program['desc'] = "" if "desc" not in request.form else request.form['desc']


        flash("New program: {} is added. Desc: {}".format(program['name'], program['desc']), category="info")
        new_prog = Software(name=program['name'], description=program['desc'])
        DB.session.add(new_prog)
        DB.session.commit()
        return redirect( url_for('programs') )

@app.route('/edit_program/<program_id>', methods=['GET', 'POST'])
def edit_program(program_id):
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()

    program = Software.query.filter_by(id_software=program_id).first()

    if program is None:
        flash("No such program", category='warning')
        return redirect(url_for('programs'))
    if request.method == 'GET':
        return render_template('edit_program.html', active_menu='programs', program=program, login=login)
    else:
        new_name = '' if 'name' not in request.form else request.form['name']
        new_desc = '' if 'desc' not in request.form else request.form['desc']

        if new_name != program.name:
            program.name = new_name
            DB.session.commit()
            flash("Email was changed", category='message')

        if new_desc != '':
            program.description = new_desc
            DB.session.commit()
            flash("Description was changed", category='message')
        return redirect(url_for('programs'))

@app.route('/program_delete/<program_id>')
def delete_program(program_id):
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    program = Software.query.filter_by(id_software=program_id).first()
    DB.session.delete(program)
    DB.session.commit()
    return redirect(url_for('programs'))

@app.route('/download/<program>/<version>')
def download_doc(program, version):
    ver = Version.query.filter(Version.id_version == version).first()
    ver = f"{ver.major_ver}.{ver.minor_ver}.{ver.sub_ver}"
    
    program_name = Software.query.filter_by(id_software=program).first().name
    file_name = 'Report_{}_{}.docx'.format(program_name, ver.replace(".", "-"))
    result = send_from_directory("data", file_name, as_attachment=True, cache_timeout=0)

    if os.path.exists("data/"+file_name):
        # return send_file(file_name, as_attachment=True)
        return result
    else:
        return redirect(url_for('features', program=program))


def gen_file(program, version):
    # Generate list of random values
    ver = Version.query.filter(Version.id_version == version).first()
    ver = f"{ver.major_ver}.{ver.minor_ver}.{ver.sub_ver}"

    titles = Title.query.filter(Title.id_software == program).filter(Title.id_version == version).all()
    content = {}
    for title in titles:
        content[title.title] = []
        for feature in title.features:
            content[title.title].append(feature.description)

    program_name = Software.query.filter_by(id_software=program).first().name

    # Import template document
    template = DocxTemplate('templates/automated_report_template.docx')
    file_name = 'Report_{}_{}.docx'.format(program_name, ver.replace(".", "-"))

    # Declare template variables
    context = {
        'version': ver,
        'day': dt.now().strftime('%d'),
        'month': dt.now().strftime('%b'),
        'year': dt.now().strftime('%Y'),
        'content': content,
    }

    # Render automated report
    template.render(context)
    
    template.save("data/"+file_name)

    return file_name


if __name__ == '__main__':
    app.run()

