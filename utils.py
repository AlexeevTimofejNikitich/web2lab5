import sqlite3
from functools import wraps

from flask import g, current_app, flash, redirect, url_for
from flask_login import current_user


def execute_query(query, args=(), one=False, modify=False):
    db = get_db()
    cur = db.execute(query, args)
    if modify:
        db.commit()
        cur.close()
        return
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


def check_rights(required_role):
    def decorator(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth'))
            if current_user.role_id > required_role:
                flash("У вас недостаточно прав для доступа к данной странице.", category="danger")
                return redirect(url_for('users'))
            return func(*args, **kwargs)
        return decorated_view
    return decorator
