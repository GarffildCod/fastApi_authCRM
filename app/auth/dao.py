from app.dao.base import BaseDAO
from app.auth.models import User



class UserDAO(BaseDAO):
    model = User