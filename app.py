import flask
from flask import render_template, redirect, url_for, request
from icecream import ic

app = flask.Flask(__name__)


@app.route('/')
def index():
    print(request.query_string)
    prog_dict = {
        'program': 0,
        'name': 'Program 1',
        'tab0': 'active',
        'tab1': '',
    }
    if 'pr' in request.args and int(request.args['pr']) == 1:
        ic()
        prog_dict['program'] = int(request.args['pr'])
        prog_dict['name'] = "Program 2"
        prog_dict['tab0'] = ''
        prog_dict['tab1'] = 'active'
    print(prog_dict)

    return render_template('base.html', pr=prog_dict)


if __name__ == '__main__':
    app.run()
