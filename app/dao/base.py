from app.db import async_session_maker
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, update



class BaseDAO:
    madel = None

    @classmethod
    async def find_by_id(cls, model_id: int):
        async with async_session_maker() as session:
            query = select(cls.model).where(cls.model.id == model_id)
            result = await session.execute(query)
            return result.scalars().first()

    @classmethod
    async def find_one_or_none(cls, **filter_by):
        async with async_session_maker() as session:
            query = select(cls.model).filter_by(**filter_by)
            result = await session.execute(query)
            return result.scalars().first()

    @classmethod
    async def find_all(cls, **filter_by):
        async with async_session_maker() as session:
            query = select(cls.model).filter_by(**filter_by)
            result = await session.execute(query)
            return result.scalars().all()

    @classmethod
    async def add(cls, **kwargs):
        async with async_session_maker() as session:
            instance = cls.model(**kwargs)
            session.add(instance)
            await session.commit()
            return instance

    @classmethod
    async def update(cls, user_id: int, **kwargs):
        """Только для update по id (("""
        async with async_session_maker() as session:
            # Обновляем атрибуты пользователя
            await session.execute(update(cls.model).where(cls.model.id == user_id).values(**kwargs))
            # Сохраняем изменения в базе данных
            await session.commit()
        
