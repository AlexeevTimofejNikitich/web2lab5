import sqlite3
import hashlib

conn = sqlite3.connect('lab5.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    last_name TEXT,
    first_name TEXT,
    middle_name TEXT,
    role_id INTEGER
)
''')

cursor.execute('''
CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL
)
''')

cursor.execute('''
CREATE TABLE visit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

# Вставка тестовых данных в таблицу roles
roles = [
    ('Admin',),
    ('User',)
]

cursor.executemany('INSERT INTO roles (name) VALUES (?)', roles)

# Получение ID ролей для связывания с пользователями
cursor.execute('SELECT id FROM roles WHERE name=?', ('Admin',))
admin_role_id = cursor.fetchone()[0]

cursor.execute('SELECT id FROM roles WHERE name=?', ('User',))
user_role_id = cursor.fetchone()[0]


# Вставка тестовых данных в таблицу users с хэшированием паролей
users = [
    ('admin', hashlib.sha256('admin'.encode()).hexdigest(), 'Admin', 'Roma', 'A', admin_role_id),
    ('user1', hashlib.sha256('user1'.encode()).hexdigest(), 'User', 'Ivan', 'B', user_role_id),
    ('user2', hashlib.sha256('user2'.encode()).hexdigest(), 'User', 'NoName', 'N', user_role_id)
]

cursor.executemany('''
INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id) 
VALUES (?, ?, ?, ?, ?, ?)
''', users)

# cursor.execute('DROP TABLE users')
# cursor.execute('DROP TABLE roles')

conn.commit()
conn.close()
