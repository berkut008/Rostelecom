from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import secrets
import os
import datetime
from jose import jwt

from database import get_db_connection, init_db
from models import AdminCreateUser
from auth import verify_password, get_password_hash, create_access_token, SECRET_KEY, ALGORITHM

# Временное хранилище логов
event_logs = []

def add_log(event: str, user: str, status: str):
    """Добавление события в лог"""
    event_logs.append({
        "timestamp": datetime.datetime.now().isoformat(),
        "event": event,
        "user": user,
        "status": status
    })
    # Оставляем только последние 1000 записей
    while len(event_logs) > 1000:
        event_logs.pop(0)

app = FastAPI(title="Ростелеком Точка Входа API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось подтвердить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        login: str = payload.get("sub")
        if login is None:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception
    return login

def get_current_admin_user(login: str = Depends(get_current_user)):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE login = ?", (login,)).fetchone()
    conn.close()
    if not user or not user['is_admin']:
        raise HTTPException(status_code=403, detail="Недостаточно прав. Требуются права администратора.")
    return login

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE login = ?", (form_data.username,)).fetchone()
    conn.close()
    if not user or not verify_password(form_data.password, user['hashed_password']):
        add_log("Попытка входа", form_data.username, "error")
        raise HTTPException(status_code=400, detail="Неверное имя пользователя или пароль")
    access_token = create_access_token(data={"sub": user['login']})
    add_log("Вход в систему", user['login'], "success")
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/admin/register", status_code=status.HTTP_201_CREATED)
async def register_user_by_admin(user: AdminCreateUser, admin_login: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    existing_user = conn.execute("SELECT * FROM users WHERE login = ?", (user.login,)).fetchone()
    if existing_user:
        conn.close()
        raise HTTPException(status_code=400, detail="Пользователь с таким логином уже существует")
    
    hashed_password = get_password_hash(user.password)
    conn.execute("INSERT INTO users (login, full_name, hashed_password, is_admin) VALUES (?, ?, ?, ?)",
                 (user.login, user.full_name, hashed_password, 0))
    conn.commit()
    conn.close()
    add_log(f"Зарегистрирован сотрудник {user.full_name}", admin_login, "success")
    return {"message": f"Пользователь {user.login} успешно зарегистрирован"}

@app.post("/generate-qr")
async def generate_qr(user_login: str = Depends(get_current_user)):
    qr_token = secrets.token_urlsafe(32)
    conn = get_db_connection()
    conn.execute("INSERT INTO qr_tokens (token, user_login) VALUES (?, ?)",
                 (qr_token, user_login))
    conn.commit()
    conn.close()
    add_log("QR-код сгенерирован", user_login, "success")
    return {"qr_value": qr_token}

@app.post("/admin/scan/{token}")
async def scan_qr(token: str, admin_login: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    qr_record = conn.execute("SELECT * FROM qr_tokens WHERE token = ? AND is_used = 0", (token,)).fetchone()
    if not qr_record:
        conn.close()
        add_log("Попытка сканирования QR", admin_login, "error")
        raise HTTPException(status_code=404, detail="Недействительный или уже использованный QR-код")
    
    conn.execute("UPDATE qr_tokens SET is_used = 1 WHERE token = ?", (token,))
    conn.commit()
    
    user = conn.execute("SELECT * FROM users WHERE login = ?", (qr_record['user_login'],)).fetchone()
    conn.close()
    add_log(f"QR-код отсканирован для {user['full_name']}", admin_login, "success")
    return {
        "message": "Доступ разрешен",
        "user": {
            "full_name": user['full_name'],
            "login": user['login']
        }
    }

@app.get("/check-qr/{token}")
async def check_qr_status(token: str):
    conn = get_db_connection()
    qr_record = conn.execute("SELECT * FROM qr_tokens WHERE token = ?", (token,)).fetchone()
    conn.close()
    if not qr_record:
        return {"status": "invalid"}
    if qr_record['is_used']:
        return {"status": "used"}
    return {"status": "active"}

# Временное хранилище для кодов подтверждения
verification_codes = {}

@app.post("/send-verification")
async def send_verification_code(request: dict):
    email = request.get('email')
    
    if not email or not email.endswith('@rt.ru'):
        raise HTTPException(status_code=400, detail="Требуется корпоративная почта @rt.ru")
    
    import random
    code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    verification_codes[email] = {
        'code': code,
        'expires': datetime.datetime.now().timestamp() + 300
    }
    
    print(f"\n=== Код подтверждения для {email}: {code} ===\n")
    return {"message": "Код отправлен", "code": code}

@app.post("/verify-code")
async def verify_code(request: dict):
    email = request.get('email')
    code = request.get('code')
    
    stored = verification_codes.get(email)
    
    if not stored:
        raise HTTPException(status_code=400, detail="Код не найден или истек")
    
    if datetime.datetime.now().timestamp() > stored['expires']:
        del verification_codes[email]
        raise HTTPException(status_code=400, detail="Код истек, запросите новый")
    
    if stored['code'] != code:
        raise HTTPException(status_code=400, detail="Неверный код подтверждения")
    
    del verification_codes[email]
    return {"message": "Код подтвержден"}

# API для админ-панели
@app.get("/admin/users")
async def get_users(admin_login: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    users = conn.execute("SELECT login, full_name, is_admin FROM users").fetchall()
    conn.close()
    return [{"login": u["login"], "full_name": u["full_name"], "is_admin": u["is_admin"]} for u in users]

@app.get("/admin/logs")
async def get_logs(admin_login: str = Depends(get_current_admin_user)):
    return event_logs[-100:]

@app.get("/admin/stats")
async def get_stats(admin_login: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    
    today = datetime.datetime.now().date().isoformat()
    today_qr = len([l for l in event_logs if l["event"] == "QR-код сгенерирован" and l["timestamp"].startswith(today)])
    success_scans = len([l for l in event_logs if l["event"] == "QR-код отсканирован" and l["status"] == "success"])
    
    return {
        "total_users": total_users,
        "today_qr": today_qr,
        "success_scans": success_scans,
        "active_sessions": 0
    }

def create_default_admin():
    conn = get_db_connection()
    admin = conn.execute("SELECT * FROM users WHERE login = 'admin@rt.ru'").fetchone()
    if not admin:
        hashed_pw = get_password_hash("admin123")
        conn.execute("INSERT INTO users (login, full_name, hashed_password, is_admin) VALUES (?, ?, ?, ?)",
                     ("admin@rt.ru", "Главный Администратор", hashed_pw, 1))
        conn.commit()
        print("Создан администратор: admin@rt.ru / admin123")
    conn.close()

create_default_admin()

# Раздача статических файлов
frontend_path = os.path.join(os.path.dirname(__file__), "../frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
async def read_index():
    return FileResponse(os.path.join(frontend_path, "login.html"))

@app.get("/dashboard")
async def read_dashboard():
    return FileResponse(os.path.join(frontend_path, "dashboard.html"))

@app.get("/admin-scan")
async def read_admin_scan():
    return FileResponse(os.path.join(frontend_path, "admin_scan.html"))

@app.get("/admin")
async def read_admin():
    return FileResponse(os.path.join(frontend_path, "admin.html"))

# Добавьте в app.py после других эндпоинтов
@app.get("/register")
async def read_register():
    return FileResponse(os.path.join(frontend_path, "register.html"))