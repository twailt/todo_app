from fastapi import FastAPI
import uvicorn

import models
from database import engine
from routers import routes, user, todos 
from starlette.staticfiles import StaticFiles



app = FastAPI()


models.Base.metadata.create_all(bind=engine)

app.mount('/static', StaticFiles(directory='static'), name='static')



app.include_router(todos.router)
app.include_router(routes.router)
app.include_router(user.router)

if __name__ == '__main__':
    uvicorn.run("main:app", reload=True)