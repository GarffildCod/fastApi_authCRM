from fastapi import APIRouter, status, Response, Depends, HTTPException, BackgroundTasks, Cookie
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from app.auth.schemas import SUserAuth, SUserPasswordReset, SUserPasswordResetAccepts
from app.auth.dao import UserDAO
from app.auth.auth import *
from app.auth.models import User
from app.auth.dependencies import get_current_user
from pydantic import BaseModel



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


# ===========
# сделать новые ключи и Убрать все в .env
SECRET_KEY='yaZGZ6uADF5MvjgVq9E96P9taSXswbJYdILuXpvMF+s='
ALGORITHM='HS256'



# ВХОД В АКАУНТ И ВЫХОД

@router.post("/login", response_model=Token)
async def login_for_access_token(
    response: Response,
    user_data: SUserAuth
):
    user = await authenticate_user(user_data.username, user_data.password.get_secret_value())
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,  
        samesite="lax", 
        secure=False,  
        max_age=1800,  
    )
    
    # токеном обновления
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=3600,  
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer"}


@router.post('/logout')
async def logout_user(respons: Response):
    """Разлог"""
    respons.delete_cookie('access_token')
    respons.delete_cookie('refresh_token')
    return {"detail": "200"}

@router.get('/gt_user')
async def get_user(current_user: User = Depends(get_current_user)):
    """Получение пользователя"""
    return current_user

# РЕГИСТРАЦИЯ АККАУНТА

@router.post('/register')
async def register_user(user_data: SUserAuth):
    """Регистрация"""
    existing_user = await UserDAO.find_one_or_none(email=user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с такой электронной почтой уже существует"
        )
    raw_password = user_data.password.get_secret_value()
    hashed_password = get_password_hash(raw_password)
    user = await UserDAO.add(email=user_data.email, username=user_data.username, hashed_password=hashed_password, confirmed=False)
    token = create_confirmation_token(user.email)
    await send_confirmation_email(user.email, token)
    return {"detail": "Пожалуйста, подтвердите свой email, чтобы завершить регистрацию."}



@router.get('/confirm/{token}')
async def confirm_email(token: str):
    """Подтверждение почты"""
    username_email = confirm_token(token)
    if not username_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ссылка для подтверждения недействительна или устарела."
        )
    user = await UserDAO.find_one_or_none(email=username_email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь не найден."
        )
    if user.confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Почта уже подтверждена."
        )
    await UserDAO.update(user.id, confirmed=True)
    return {"detail": "Почта успешно подтверждена. Спасибо!"}




# Востановления пароля

@router.post('/request-password-reset')
async def request_password_reset(user_data: SUserPasswordResetAccepts, background_tasks: BackgroundTasks):
    """Запрос на восстановление пароля"""
    user = await UserDAO.find_one_or_none(email=user_data.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователя с такой электронной почтой не существует"
        )
    token = create_password_reset_token(user.email)
    background_tasks.add_task(send_password_reset_email, user.email, token)
    return {"detail": "На вашу почту отправлена ссылка для восстановления пароля."}


@router.post('/reset-password/{token}')
async def reset_password(token: str, user_data: SUserPasswordReset):
    """Установка нового пароля"""
    email = confirm_password_reset_token(token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ссылка для восстановления пароля недействительна или устарела."
        )
    user = await UserDAO.find_one_or_none(email=email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь не найден."
        )
    raw_password = user_data.new_password.get_secret_value()
    hashed_password = get_password_hash(raw_password)
    await UserDAO.update(user.id, hashed_password=hashed_password)
    return {"detail": "Пароль успешно изменен."}

@router.post("/refresh", response_model=Token)
async def refresh_token(response: Response,
    refresh_token: str = Cookie(None)):
    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не удалось проверить учетные данные",
            headers={"WWW-Authenticate": "Bearer"},
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось проверить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # Проверяем, что пользователь существует 
    user = await UserDAO.find_one_or_none(username=username)
    if user is None:
        raise credentials_exception

    # Создаем новый токен доступа и рефреш токен
    access_token = create_access_token(data={"sub": username})
    refresh_token = create_refresh_token(data={"sub": username})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,  
        samesite="lax", 
        secure=False,  
        max_age=1800,  
    )
    # токеном обновления
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=3600,  
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer"}