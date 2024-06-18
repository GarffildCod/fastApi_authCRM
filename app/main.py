from fastapi import FastAPI

from app.auth.router import router as router_auth
# Инициализация
app = FastAPI(title="yurCRM")



app.include_router(router_auth)


