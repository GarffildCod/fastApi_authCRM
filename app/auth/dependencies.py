from fastapi import Request, HTTPException, Depends, status
from jose import jwt, JWTError

from datetime import datetime
from app.auth.dao import UserDAO

SECRET_KEY='yaZGZ6uADF5MvjgVq9E96P9taSXswbJYdILuXpvMF+s='
ALGORITHM='HS256'

def get_token(request: Request):
    # распознаем пользователя
    token = request.cookies.get('access_token')
    if not token:
        raise HTTPException(status_code=401, detail="I")
    return token

async def get_current_user(token: str = Depends(get_token)):
    try:
        payload = jwt.decode(token, 
                             SECRET_KEY, algorithm=ALGORITHM)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="I1")
    expire: str = payload.get('exp')
    if (not expire) or (int(expire)) < datetime.utcnow().timestamp():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="I2")
    user_id: str = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="I3")
    user = await UserDAO.find_by_id(int(user_id))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="I4")
    return user