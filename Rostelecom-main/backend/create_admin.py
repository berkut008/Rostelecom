# create_admin.py
import sqlite3
import hashlib

SALT = "rostelecom_salt_2026"  # ← такая же соль, как в твоём auth.py

def get_password_hash(password):
    return hashlib.sha256(f"{password}{SALT}".encode()).hexdigest()

conn = sqlite3.connect('users.db')
cursor = conn.cursor()

login = "admin"
password = "admin123"
full_name = "Администратор"
email = "admin@rt.ru"
hashed_password = get_password_hash(password)

cursor.execute("""
    INSERT OR REPLACE INTO users 
    (login, full_name, hashed_password, email, is_admin, is_active)
    VALUES (?, ?, ?, ?, 1, 1)
""", (login, full_name, hashed_password, email))

conn.commit()
conn.close()

print("Администратор успешно создан!")
print("Логин:    admin")
print("Пароль:   admin123")
print("Теперь можешь войти через /token")