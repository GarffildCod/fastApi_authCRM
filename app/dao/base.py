from app.db import async_session_maker
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert


class BaseDAO:
    madel = None

    # @classmethod
    # async def find_by_id(cls, model_id: int):
    #      async with async_session_maker() as session:
    #         query = select(cls.madel).filter_by(id=model_id)
    #         result = await session.execute(query)
    #         return result.scalars_find_by_id()

    # @classmethod
    # async def find_one_or_none(cls, **filter_by):
    #     async with async_session_maker() as session:
    #         query = select(cls.madel).filter_by(**filter_by)
    #         result = await session.execute(query)
    #         return result.scalars_one_or_none()

    # @classmethod
    # async def find_all(cls, **filter_by):
    #     async with async_session_maker() as session:
    #         query = select(cls.madel).filter_by(**filter_by)
    #         result = await session.execute(query)
    #         return result.scalars().all()
        
    # @classmethod
    # async def add(cls, **data):
    #     async with async_session_maker() as session:
    #         query = insert(cls.model).values(**data)
    #         await session.execute(query)
    #         await session.commit() 

    @classmethod
    async def find_by_id(cls, session: AsyncSession, model_id: int):
        query = select(cls.model).where(cls.model.id == model_id)
        result = await session.execute(query)
        return result.scalars().first()

    @classmethod
    async def find_one_or_none(cls, session: AsyncSession, **filter_by):
        query = select(cls.model).filter_by(**filter_by)
        result = await session.execute(query)
        return result.scalars().first()

    @classmethod
    async def find_all(cls, session: AsyncSession, **filter_by):
        query = select(cls.model).filter_by(**filter_by)
        result = await session.execute(query)
        return result.scalars().all()

    @classmethod
    async def add(cls, session: AsyncSession, **kwargs):
        instance = cls.model(**kwargs)
        session.add(instance)
        await session.commit()
        return instance

    @classmethod
    async def update(cls, session: AsyncSession, instance, **kwargs):
        for key, value in kwargs.items():
            setattr(instance, key, value)
        await session.commit()
        return instance