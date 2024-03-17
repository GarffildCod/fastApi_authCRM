from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt ,JWTError
from fastapi import HTTPException, status
from app.auth.dao import UserDAO
from pydantic import EmailStr
from app.config import settings
# ----
from itsdangerous import URLSafeTimedSerializer
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# мусор который надо разобрать
serializer = URLSafeTimedSerializer("8QQogqSjhgHz2mx4lYZweRZOkyfe0Pmc2Lf93VHeO1A=")
rand_salt_key = '212cjn9XCY6lnVAX6uhTyo9bRm57gqD54ukrUN6cNTI='
# conf = ConnectionConfig(
#     MAIL_USERNAME="your_email@example.com",  # Ваш email для авторизации на SMTP-сервере
#     MAIL_PASSWORD="your_password",  # Ваш пароль для авторизации на SMTP-сервере
#     MAIL_FROM="your_email@example.com",  # Email адрес отправителя
#     MAIL_PORT=587,  # Порт SMTP-сервера (для почты на Gmail обычно используется 587)
#     MAIL_SERVER="smtp.example.com",  # SMTP-сервер (для Gmail это smtp.gmail.com)
#     MAIL_FROM_NAME="Your Name",  # Имя отправителя
#     MAIL_TLS=True,  # Используется ли TLS (для Gmail это True)
#     MAIL_SSL=False,  # Используется ли SSL (для Gmail это False)
#     USE_CREDENTIALS=True,  # Используются ли учетные данные для авторизации (обычно True)
#     VALIDATE_CERTS=True,  # Проверять ли сертификаты SSL (обычно True)
#     TEMPLATE_FOLDER='./templates'  # Путь к папке с шаблонами писем
# )



def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=3600)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, 
                             settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def authenticate_user(email: EmailStr, password: str):
    user = await UserDAO.find_one_or_none(email=email)
    if not user and verify_password(password, user.password):
        return None
    return user

# Sign up

# Функции для создания токена подтверждения
def create_confirmation_token(email: str):
    return serializer.dumps(email, salt=rand_salt_key)

# Функция для подтверждения токена
def confirm_token(token: str, expiration: int = 3600):
    try:
        email = serializer.loads(
            token,
            salt=rand_salt_key,
            max_age=expiration
        )
    except:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ссылка для подтверждения недействительна или устарела."
        )
    return email

# # Функция для подтверждения токена
# def confirm_token(token: str, expiration: int = 3600):
#     try:
#         email = serializer.loads(
#             token,
#             salt=settings.SECRET_SALT,
#             max_age=expiration
#         )
#     except (BadSignature, SignatureExpired):
#         return None
#     return email


# Функция для отправки email с подтверждением
# async def send_confirmation_email(email: str, token: str):
#     message = MessageSchema(
#         subject="Подтверждение регистрации",
#         recipients=[email],
#         body=f"Для подтверждения регистрации перейдите по ссылке: {settings.BASE_URL}/auth/confirm/{token}",
#     )
#     fm = FastMail(conf)
#     await fm.send_message(message)


# Password Recovery

    # Функция для создания токена восстановления пароля
def create_password_reset_token(email: str):
    return serializer.dumps(email, salt=rand_salt_key)

# Функция для подтверждения токена восстановления пароля
def confirm_password_reset_token(token: str, expiration: int = 3600):
    try:
        email = serializer.loads(
            token,
            salt=rand_salt_key,
            max_age=expiration
        )
    except:
        return None
    return email

# Функция для отправки email с ссылкой на восстановление пароля
# async def send_password_reset_email(email: str, token: str):
#     message = MessageSchema(
#         subject="Восстановление пароля",
#         recipients=[email],
#         body=f"Для восстановления пароля перейдите по ссылке: {settings.BASE_URL}/auth/reset-password/{token}",
#     )
#     fm = FastMail(conf)
#     await fm.send_message(message)