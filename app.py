from flask import Flask, render_template, session, request, redirect, url_for, flash, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import sqlite3
import hashlib
from data_valid import validate_user_data, validate_password_data
from utils import execute_query, check_rights

app = Flask(__name__)
application = app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lab5.db'
app.config['SECRET_KEY'] = 'roma'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth"
login_manager.login_message = "Войдите, чтобы просматривать содержимое данной страницы"
login_manager.login_message_category = "warning"

from reports import bp
app.register_blueprint(bp)

CREATE_USER_FIELDS = ['login', 'password', 'last_name', 'first_name', 'middle_name', 'role_id']
EDIT_USER_FIELDS = ['last_name', 'first_name', 'middle_name', 'role_id']


class User(UserMixin):
    def __init__(self, user_id, login, role_id):
        self.id = user_id
        self.login = login
        self.role_id = role_id

def get_roles():
    query = "SELECT * FROM roles"
    roles = execute_query(query)
    return roles


@login_manager.user_loader
def load_user(user_id):
    query = "SELECT id, login, role_id FROM users WHERE id=?"
    user = execute_query(query, (user_id,), one=True)
    if user:
        return User(user['id'], user['login'], user['role_id'])
    return None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/info')
def info():
    session['counter'] = session.get('counter', 0) + 1
    return render_template('info.html')


@app.route('/auth', methods=["GET", "POST"])
def auth():
    if request.method == "GET":
        return render_template("auth.html")

    login = request.form.get("login", "")
    password = request.form.get("pass", "")
    remember = request.form.get("remember") == "on"

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    query = 'SELECT id, login, role_id FROM users WHERE login=? AND password_hash=?'

    user = execute_query(query, (login, password_hash), one=True)

    if user:
        login_user(User(user['id'], user['login'], user["role_id"]), remember=remember)
        flash("Успешная авторизация", category="success")
        target_page = request.args.get("next", url_for("index"))
        return redirect(target_page)

    flash("Введены некорректные учётные данные пользователя", category="danger")
    return render_template("auth.html")


@app.route('/users')
def users():
    query = 'SELECT users.*, roles.name as role_name FROM users LEFT JOIN roles ON users.role_id = roles.id'
    data = execute_query(query)
    print(1)
    print(current_user.role_id)
    return render_template("users.html", users=data)


def get_form_data(required_fields):
    form_data = {}
    for field in required_fields:
        form_data[field] = request.form.get(field) or None
    return form_data


@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    roles = get_roles()
    user = execute_query(query, (user_id,), one=True)

    print(current_user.role_id)

    if current_user.role_id == 2 and current_user.id != user_id:
        flash("У вас недостаточно прав для редактирования этого пользователя.", "danger")
        return redirect(url_for("users"))

    if request.method == "POST":
        form_data = get_form_data(EDIT_USER_FIELDS)
        form_data['user_id'] = user_id
        query = "UPDATE users SET last_name=?, first_name=?, middle_name=?, role_id=? WHERE id=?"
        try:
            execute_query(query, (
            form_data['last_name'], form_data['first_name'], form_data['middle_name'], form_data['role_id'], user_id), modify=True)
            flash("Запись пользователя успешно обновлена", category="success")
            return redirect(url_for('users'))
        except sqlite3.DatabaseError as error:
            flash(f'Ошибка редактирования пользователя! {error}', category="danger")

    return render_template("edit_user.html", user=user, roles=roles)


@app.route('/user/<int:user_id>/delete', methods=["POST"])
@login_required
@check_rights(1)
def delete_user(user_id):
    query = "DELETE FROM users WHERE id=?"
    try:
        execute_query(query, (user_id,), modify=True)
        flash("Запись пользователя успешно удалена", category="success")
    except sqlite3.DatabaseError as error:
        flash(f'Ошибка удаления пользователя! {error}', category="danger")

    return redirect(url_for('users'))


@app.route('/users/new', methods=['GET', 'POST'])
@login_required
@check_rights(1)
def create_user():
    roles = get_roles()
    user = {}
    errors = {}
    if request.method == 'POST':
        form_data = get_form_data(CREATE_USER_FIELDS)
        errors = validate_user_data(form_data['login'], form_data['password'], form_data['first_name'],
                                    form_data['last_name'])

        if not errors:
            form_data['password_hash'] = hashlib.sha256(form_data['password'].encode()).hexdigest()
            query = ("INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id) "
                     "VALUES (?, ?, ?, ?, ?, ?)")
            try:
                execute_query(query, (
                form_data['login'], form_data['password_hash'], form_data['last_name'], form_data['first_name'],
                form_data['middle_name'], form_data['role_id']), modify=True)
                return redirect(url_for('users'))
            except sqlite3.DatabaseError as error:
                flash(f'Ошибка создания пользователя! {error}', category="danger")
        else:
            flash("Пожалуйста, исправьте ошибки в форме.", category="danger")

    print(errors)
    return render_template("user_form.html", roles=roles, user=user, errors=errors)

#todo: ошибки под полями, encode(), запятая в query_db, валидация нового пароля
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not old_password or not new_password or not confirm_password:
            flash("Все поля должны быть заполнены", category="danger")
        elif new_password != confirm_password:
            flash("Новый пароль и подтверждение пароля не совпадают", category="danger")
        else:
            errors = validate_password_data(new_password)
            if not errors:
                query = "SELECT password_hash FROM users WHERE id=?"
                user = execute_query(query, (current_user.id,), one=True)
                if user and hashlib.sha256(old_password.encode()).hexdigest() == user['password_hash']:
                    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
                    update_query = "UPDATE users SET password_hash=? WHERE id=?"
                    try:
                        execute_query(update_query, (new_password_hash, current_user.id), modify=True)
                        flash("Пароль успешно изменен", category="success")
                        return redirect(url_for('index'))
                    except sqlite3.DatabaseError as error:
                        flash(f'Ошибка при изменении пароля! {error}', category="danger")
                else:
                    flash("Возникла ошибка, попробуйте снова.", category="danger")
            else:
                for field, error_message in errors.items():
                    flash(f"{error_message}", category="danger")

    return render_template('change_password.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html')


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.before_request
def log_visit():
    if request.endpoint not in ['static']:
        path = request.path
        user_id = current_user.id if current_user.is_authenticated else None
        query = "INSERT INTO visit_logs (path, user_id) VALUES (?, ?)"
        execute_query(query, (path, user_id), modify=True)


if __name__ == '__main__':
    app.run(debug=True, port=5000)