from fastapi import FastAPI

from app.auth.router import router as router_auth
# Инициализация
app = FastAPI(title="yurCRM")

@app.get("/")
def read_root():
    return {"Hello": "World"}

app.include_router(router_auth, 
                prefix='/auth',
                tags = ['Пользователь'])


