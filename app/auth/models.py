from sqlalchemy import Column, Integer, String, Boolean
from app.db import Base

class User(Base):
    __tablename__ = 'User'
    id = Column(Integer, primary_key=True, nullable=False)
    username = Column(String, unique=True, nullable=False) 
    email = Column(String, unique=True, nullable=False)  #
    hashed_password = Column(String, nullable=False)
    confirmed = Column(Boolean, default=False, nullable=False)