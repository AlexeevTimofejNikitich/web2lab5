import re

def validate_user_data(login, password, first_name, last_name):
    errors = {}

    # Проверка на пустые поля
    if not login:
        errors['login'] = "Поле логин не может быть пустым"
    if not first_name:
        errors['first_name'] = "Поле имя не может быть пустым"
    if not last_name:
        errors['last_name'] = "Поле фамилия не может быть пустым"

    # Проверка логина
    if login and not re.match(r'^[a-zA-Z0-9]{5,}$', login):
        errors['login'] = "Логин должен состоять только из латинских букв и цифр и иметь длину не менее 5 символов"

    # Проверка пароля
    password_errors = validate_password_data(password)
    if password_errors:
        errors.update(password_errors)

    return errors

def validate_password_data(password):
    errors = {}

    if not password:
        errors['password'] = "Поле пароль не может быть пустым"
    else:
        # Проверка пароля
        if len(password) < 8 or len(password) > 128:
            errors['password'] = "Пароль должен быть не менее 8 и не более 128 символов"
        if not re.search(r'[A-Z]', password):
            errors['password'] = "Пароль должен содержать как минимум одну заглавную букву"
        if not re.search(r'[a-z]', password):
            errors['password'] = "Пароль должен содержать как минимум одну строчную букву"
        if not re.search(r'[0-9]', password):
            errors['password'] = "Пароль должен содержать как минимум одну цифру"
        if re.search(r'\s', password):
            errors['password'] = "Пароль не должен содержать пробелов"
        if not re.match(r'^[a-zA-Z0-9~!?@#$%^&*_\-+()\[\]{}><\/\\|"\'.,:;]+$', password):
            errors['password'] = "Пароль содержит недопустимые символы"

    return errors
