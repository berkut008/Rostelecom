from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import secrets
import os

from database import get_db_connection, init_db
from models import AdminCreateUser
from auth import verify_password, get_password_hash, create_access_token, SECRET_KEY, ALGORITHM

# --- Инициализация приложения ---
app = FastAPI(title="Ростелеком Точка Входа API")

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Инициализация базы данных
init_db()

# Настройка OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Вспомогательные функции ---
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
    except JWTError:
        raise credentials_exception
    return login

def get_current_admin_user(login: str = Depends(get_current_user)):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE login = ?", (login,)).fetchone()
    conn.close()
    if not user or not user['is_admin']:
        raise HTTPException(status_code=403, detail="Недостаточно прав. Требуются права администратора.")
    return login

# --- Эндпоинты API ---

# Для получения токена (логин/пароль)
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE login = ?", (form_data.username,)).fetchone()
    conn.close()
    if not user or not verify_password(form_data.password, user['hashed_password']):
        raise HTTPException(status_code=400, detail="Неверное имя пользователя или пароль")
    access_token = create_access_token(data={"sub": user['login']})
    return {"access_token": access_token, "token_type": "bearer"}

# Регистрация пользователя (ТОЛЬКО ДЛЯ АДМИНА)
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
    return {"message": f"Пользователь {user.login} успешно зарегистрирован"}

# Генерация QR-кода
@app.post("/generate-qr")
async def generate_qr(user_login: str = Depends(get_current_user)):
    qr_token = secrets.token_urlsafe(32)
    conn = get_db_connection()
    conn.execute("INSERT INTO qr_tokens (token, user_login) VALUES (?, ?)",
                 (qr_token, user_login))
    conn.commit()
    conn.close()
    return {"qr_value": qr_token}

# Проверка QR-кода (симуляция сканера)
@app.post("/admin/scan/{token}")
async def scan_qr(token: str, admin_login: str = Depends(get_current_admin_user)):
    conn = get_db_connection()
    qr_record = conn.execute("SELECT * FROM qr_tokens WHERE token = ? AND is_used = 0", (token,)).fetchone()
    if not qr_record:
        conn.close()
        raise HTTPException(status_code=404, detail="Недействительный или уже использованный QR-код")
    
    conn.execute("UPDATE qr_tokens SET is_used = 1 WHERE token = ?", (token,))
    conn.commit()
    
    user = conn.execute("SELECT * FROM users WHERE login = ?", (qr_record['user_login'],)).fetchone()
    conn.close()
    return {
        "message": "Доступ разрешен",
        "user": {
            "full_name": user['full_name'],
            "login": user['login']
        }
    }

# Проверка статуса QR
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

# --- Создание администратора ---
def create_default_admin():
    conn = get_db_connection()
    admin = conn.execute("SELECT * FROM users WHERE login = 'admin'").fetchone()
    if not admin:
        hashed_pw = get_password_hash("admin123")
        conn.execute("INSERT INTO users (login, full_name, hashed_password, is_admin) VALUES (?, ?, ?, ?)",
                     ("admin", "Главный Администратор", hashed_pw, 1))
        conn.commit()
        print("Создан администратор по умолчанию: login='admin', password='admin123'")
    conn.close()

create_default_admin()

# --- Раздача статических файлов ---
frontend_path = os.path.join(os.path.dirname(__file__), "../frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
async def read_index():
    frontend_path_local = os.path.join(os.path.dirname(__file__), "../frontend")
    return FileResponse(os.path.join(frontend_path_local, "login.html"))

@app.get("/dashboard")
async def read_dashboard():
    frontend_path_local = os.path.join(os.path.dirname(__file__), "../frontend")
    return FileResponse(os.path.join(frontend_path_local, "dashboard.html"))

@app.get("/admin-scan")
async def read_admin_scan():
    frontend_path_local = os.path.join(os.path.dirname(__file__), "../frontend")
    return FileResponse(os.path.join(frontend_path_local, "admin_scan.html"))