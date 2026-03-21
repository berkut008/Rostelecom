from jose import JWTError, jwt
import datetime
import hashlib
import secrets

SECRET_KEY = "rostelecom-secret-key-2024-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 день

# Простое хеширование для демо (без bcrypt)
def verify_password(plain_password, hashed_password):
    """Проверка пароля"""
    return get_password_hash(plain_password) == hashed_password

def get_password_hash(password):
    """Простое хеширование для демо"""
    salt = "rostelecom_salt_2024"
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt