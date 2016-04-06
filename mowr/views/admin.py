from flask import render_template, Blueprint, current_app, session, redirect, url_for, request, flash, abort
admin = Blueprint('admin', __name__, url_prefix='/admin')


@admin.route('/')
def index():
    if 'login' in session:
        return render_template('admin.html')
    return redirect(url_for('admin.login'))


@admin.route('/login', methods=['GET', 'POST'])
def login():
    if 'login' in session:
        return redirect(url_for('admin.index'))

    if request.method == 'POST':
        # Check input
        print(request.form)
        if request.form.get('password') == current_app.config['ADMIN_PASSWORD'] and request.form.get('login') == current_app.config['ADMIN_LOGIN']:
            session['login'] = request.form.get('login')
            return redirect(url_for('admin.index'))
        else:
            flash('Sorry, are you sure about what you are doing ?', 'danger')

    return render_template('login.html')
