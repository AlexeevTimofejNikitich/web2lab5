from io import StringIO

from flask import Blueprint, render_template, request, send_file
import csv
from utils import execute_query, check_rights


bp = Blueprint('reports', __name__, url_prefix='/reports')



@bp.route('/visits')
def visit_logs():
    print("@bp.route('/visits')")
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    query = """
    SELECT visit_logs.id, users.first_name || ' ' || users.last_name as user_name, visit_logs.path, visit_logs.created_at
    FROM visit_logs LEFT JOIN users ON visit_logs.user_id = users.id
    ORDER BY visit_logs.created_at DESC
    LIMIT ? OFFSET ?
    """
    data = execute_query(query, (per_page, offset))
    query_total = "SELECT COUNT(*) as total FROM visit_logs"
    total = execute_query(query_total, one=True)['total']
    return render_template('visit_logs.html', visit_logs=data, page=page, per_page=per_page, total=total)


@bp.route('/pages')
def page_stats():
    print("@bp.route('/pages')")
    query = """
    SELECT path, COUNT(*) as visit_count
    FROM visit_logs
    GROUP BY path
    ORDER BY visit_count DESC
    """
    data = execute_query(query)
    return render_template('page_stats.html', page_stats=data)


@bp.route('/pages/export')
def export_page_stats():
    print("@bp.route('/pages/export')")
    query = """
    SELECT path, COUNT(*) as visit_count
    FROM visit_logs
    GROUP BY path
    ORDER BY visit_count DESC
    """
    data = execute_query(query)

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Страница', 'Количество посещений'])
    cw.writerows([(row['path'], row['visit_count']) for row in data])
    response = app.response_class(
        si.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=page_stats.csv"}
    )
    return response


@bp.route('/users')
def user_stats():
    print("@bp.route('/users')")
    query = """
    SELECT users.first_name || ' ' || users.last_name as user_name, COUNT(*) as visit_count
    FROM visit_logs LEFT JOIN users ON visit_logs.user_id = users.id
    GROUP BY visit_logs.user_id
    ORDER BY visit_count DESC
    """
    data = execute_query(query)
    return render_template('user_stats.html', user_stats=data)


@bp.route('/users/export')
def export_user_stats():
    print("@bp.route('/users/export')")
    query = """
    SELECT users.first_name || ' ' || users.last_name as user_name, COUNT(*) as visit_count
    FROM visit_logs LEFT JOIN users ON visit_logs.user_id = users.id
    GROUP BY visit_logs.user_id
    ORDER BY visit_count DESC
    """
    data = execute_query(query)

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Пользователь', 'Количество посещений'])
    cw.writerows([(row['user_name'], row['visit_count']) for row in data])
    response = app.response_class(
        si.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=user_stats.csv"}
    )
    return response
