from flask import render_template, Blueprint, current_app, session, redirect, url_for, request, flash
from mowr.model.db import Sample
import os
admin = Blueprint('admin', __name__, url_prefix='/admin')


@admin.route('/')
def index():
    if not 'login' in session:
        return redirect(url_for('admin.login'))

    file_number = Sample.objects.count()
    file_size = sum(os.path.getsize('{0}/{1}'.format(current_app.config['UPLOAD_FOLDER'], f)) for f in os.listdir(current_app.config['UPLOAD_FOLDER']))
    return render_template('admin.html', file_number=file_number, file_size=file_size)


@admin.route('/login', methods=['GET', 'POST'])
def login():
    if 'login' in session:
        return redirect(url_for('admin.index'))

    if request.method == 'POST':
        # Check input
        if request.form.get('password') == current_app.config['ADMIN_PASSWORD'] and request.form.get('login') == current_app.config['ADMIN_LOGIN']:
            session['login'] = request.form.get('login')
            return redirect(url_for('admin.index'))
        else:
            flash('Sorry, are you sure about what you are doing ?', 'danger')

    return render_template('login.html')
