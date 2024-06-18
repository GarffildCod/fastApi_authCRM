from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt ,JWTError
from fastapi import HTTPException, status
from app.auth.dao import UserDAO
from pydantic import EmailStr
# from app.config import settings
# from app.db import async_session_maker
from itsdangerous import URLSafeTimedSerializer
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ===========
# сделать новые ключи и Убрать все в .env
serializer = URLSafeTimedSerializer("8QQogqSjhgHz2mx4lYZweRZOkyfe0Pmc2Lf93VHeO1A=")
rand_salt_key_confir = '212cjn9XCY6lnVAX6uhT='
rand_salt_key_recover = '212cjn9XCY6lnVAX6uhT='
SECRET_KEY='yaZGZ6uADF5MvjgVq9E96P9taSXswbJYdILuXpvMF+s='
ALGORITHM='HS256'
conf = ConnectionConfig(
    MAIL_USERNAME="egorkolen@yandex.ru",
    MAIL_PASSWORD='hzifnyloidficrre',
    MAIL_FROM="egorkolen@yandex.ru",
    MAIL_PORT= 465,
    MAIL_SERVER="smtp.yandex.ru",
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=True,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=False,
)
BASE_URL = 'localhost'
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 минут
REFRESH_TOKEN_EXPIRE_MINUTES = 10080  # 7 дней
# ===========

def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, 
                             SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    reencoded_jwt = jwt.encode(to_encode, 
                             SECRET_KEY, algorithm=ALGORITHM)
    return reencoded_jwt

async def authenticate_user(username: str, password: str):
    # async with async_session_maker() as session:
    user = await UserDAO.find_one_or_none(username=username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user
    
# Sign up
    
# Функции для создания токена подтверждения email
def create_confirmation_token(email: str):
    return serializer.dumps(email, salt=rand_salt_key_confir)

# Функция для подтверждения токена email 
def confirm_token(token: str, expiration: int = 3600):
    try:
        confirmation_em = serializer.loads(
            token,
            salt=rand_salt_key_confir,
            max_age=expiration
        )
    except:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ссылка для подтверждения недействительна или устарела."
        )
    return confirmation_em


# Функция для отправки email с подтверждением
async def send_confirmation_email(email: str, token: str):
    message = MessageSchema(
        subject="Подтверждение регистрации",
        body=f"Для подтверждения регистрации перейдите по ссылке: {BASE_URL}/auth/confirm/{token}",
        recipients=[email],
        subtype="html" 
    )
    fm = FastMail(conf)
    await fm.send_message(message)


# Password Recovery

# Функция для создания токена восстановления пароля
def create_password_reset_token(email: str):
    return serializer.dumps(email, salt=rand_salt_key_recover)

# Функция для подтверждения токена восстановления пароля
def confirm_password_reset_token(token: str, expiration: int = 3600):
    try:
        confirmation_ps = serializer.loads(
            token,
            salt=rand_salt_key_recover,
            max_age=expiration
        )
    except:
        return None
    return confirmation_ps

# Функция для отправки email с ссылкой на восстановление пароля
async def send_password_reset_email(email: str, token: str):
    html_content = f"""
    <html>
    <body>
        <p>Для восстановления пароля перейдите по ссылке:</p>
        <a href="{BASE_URL}/auth/reset-password/{token}">Восстановить пароль</a>
    </body>
    </html>
    """
    message = MessageSchema(
        subject="Восстановление пароля",
        recipients=[email],
        body=html_content,
        subtype="html" 
    )
    fm = FastMail(conf)
    await fm.send_message(message)