from fastapi import Request, HTTPException, Depends, status
from jose import jwt, JWTError
from app.config import settings
from datetime import datetime
from app.auth.dao import UserDAO


def get_token(request: Request):
    # распознаем пользователя
    token = request.cookies.get('web-app-sessian')
    if not token:
        raise HTTPException(status_code=401)
    return token

async def get_current_user(token: str = Depends(get_token)):
    try:
        payload = jwt.decode(token, 
                             settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    expire: str = payload.get('exp')
    if (not expire) or (int(expire)) < datetime.utcnow().timestamp():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    user_id: str = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    user = await UserDAO.find_by_id(int(user_id))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return user