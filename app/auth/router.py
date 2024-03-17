from fastapi import APIRouter, status, Response, Depends, HTTPException, BackgroundTasks

from app.auth.schemas import SUserAuth, SUserPasswordReset
from app.auth.dao import UserDAO
from app.auth.auth import *
from app.auth.models import User
from app.auth.dependencies import get_current_user




router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


SERIALLZER_SECRET_KEY='8QQogqSjhgHz2mx4lYZweRZOkyfe0Pmc2Lf93VHeO1A='

rand_salt_key = '212cjn9XCY6lnVAX6uhTyo9bRm57gqD54ukrUN6cNTI='

SECRET_KEY='yaZGZ6uADF5MvjgVq9E96P9taSXswbJYdILuXpvMF+s='
ALGORITHM='HS256'



@router.post('/login')
async def login_user(response: Response, user_data: SUserAuth):
    """Залогинется"""
    user = authenticate_user(user_data.email, user_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный email или пароль"
        )
    if not user.confirmed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь не подтвержден. Проверьте свою почту для подтверждения."
        )
    access_token = create_access_token({'sub': str(user.id)})
    response.set_cookie('web-app-sessian', access_token, httponly=True)
    return {"detail": "OK"}


@router.post('/logout')
async def logout_user(respons: Response):
    """Разлог"""
    respons.delete_cookie('web-app-sessian')

@router.get('/gt_user')
async def get_user(current_user: User = Depends(get_current_user)):
    """Получение пользователя"""
    return current_user

# ---------

@router.post('/register')
async def register_user(user_data: SUserAuth):
    """Регистрация"""
    existing_user = await UserDAO.find_one_or_none(email=user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email уже существует"
        )
    hashed_password = get_password_hash(user_data.password)
    user = await UserDAO.add(email=user_data.email, hashed_password=hashed_password, confirmed=False)
    token = create_confirmation_token(user.email)
    await send_confirmation_email(user.email, token)
    return {"detail": "Пожалуйста, подтвердите свой email, чтобы завершить регистрацию."}



@router.get('/confirm/{token}')
async def confirm_email(token: str):
    """Возвращает подтверждение"""
    email = confirm_token(token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ссылка для подтверждения недействительна или устарела."
        )
    user = await UserDAO.find_one_or_none(email=email)
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
    await UserDAO.update(user, confirmed=True)
    return {"detail": "Почта успешно подтверждена. Спасибо!"}



# =====================
    # Востановления пароля

@router.post('/request-password-reset')
async def request_password_reset(user_data: SUserAuth, background_tasks: BackgroundTasks):
    """Запрос на восстановление пароля"""
    user = await UserDAO.find_one_or_none(email=user_data.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email не найден"
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
    hashed_password = get_password_hash(user_data.new_password)
    await UserDAO.update(user, hashed_password=hashed_password)
    return {"detail": "Пароль успешно изменен."}



@auth_router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}