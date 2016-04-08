from flask import render_template, Blueprint, current_app, session, redirect, url_for, request, flash, abort
from mowr.model.db import Sample
from datetime import datetime
import os

admin = Blueprint('admin', __name__, url_prefix='/admin', static_folder='../static_admin', static_url_path='/static')


@admin.route('/')
def index():
    if 'login' not in session:
        return redirect(url_for('admin.login'))
    elif session.get('login') == current_app.config['ADMIN_LOGIN']:
        return render_template('admin/index.html', stats=getstats())
    abort(404)


@admin.route('/login', methods=['GET', 'POST'])
def login():
    if 'login' in session:
        return redirect(url_for('admin.index'))

    if request.method == 'POST':
        # Check input
        if request.form.get('password') == current_app.config['ADMIN_PASSWORD']:
            if request.form.get('login') == current_app.config['ADMIN_LOGIN']:
                session['login'] = request.form.get('login')
                return redirect(url_for('admin.index'))
        else:
            flash('Sorry, are you sure about what you are doing ?', 'danger')

    return render_template('admin/login.html')


@admin.route('/logout')
def logout():
    session.pop('login', None)
    return redirect(url_for('default.index'))


def getstats():
    """ Returns a dict containing statistics """
    ## Disk usage
    # Count samples in the database
    samplesNb = Sample.objects.count()
    # Count the samples size
    file_size = sum(os.path.getsize('{0}/{1}'.format(current_app.config['UPLOAD_FOLDER'], f)) for f in
                    os.listdir(current_app.config['UPLOAD_FOLDER']))
    st = os.statvfs(current_app.config.get('UPLOAD_FOLDER'))
    # Compute free space
    remaining_storage = st.f_bavail * st.f_frsize

    diskUsage = dict(
        file_size=file_size,
        remaining_storage=remaining_storage
    )

    ## Graph 1
    # Last 7 days dates from oldest to newest
    dateList = list(reversed([datetime.fromtimestamp(datetime.utcnow().timestamp() - 3600 * 24 * i) for i in range(7)]))
    dateList = [i.replace(minute=0, hour=0, second=0, microsecond=0) for i in dateList]
    # Count the samples
    data1 = [Sample.objects(first_analysis__gte=dateList[i], first_analysis__lt=dateList[i + 1]).count() for i in
             range(len(dateList) - 1)]
    data1.append(Sample.objects(first_analysis__gte=dateList[len(dateList) - 1]).count())

    samplesChart = dict(
        # Get only the year-day-month
        dateList=[i.date().isoformat() for i in dateList],
        data1=data1,
        data2=[0] * 7
    )

    ## File types
    # Get mime types from database
    rates = Sample.objects.item_frequencies('mime')
    stats = [v for i, v in rates.items()]
    types = [i for i in rates]

    fileType = dict(
        stats=stats,
        types=types
    )
    print(stats, types, rates)

    return dict(
        samplesNb=samplesNb,
        samplesChart=samplesChart,
        diskUsage=diskUsage,
        fileType=fileType
    )
