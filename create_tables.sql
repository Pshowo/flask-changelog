create table software (id_software integer primary key AUTOINCREMENT, name varchar(30));
create table version (id_version integer primary key autoincrement, id_soft integer, major_ver integer, minor_ve
r integer, sub_ver integer);
create table author (id_author integer primary key autoincrement, initial varchar(3));
create table features(id_features integer primary key autoincrement, id_version integer, date not null default(date()), description text, id_author integer, link varchar(250), title varchar(200));
create table email(id_email integer primary key AUTOINCREMENT, email varchar(100));
