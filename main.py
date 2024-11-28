from fastapi import FastAPI
from src.routers.user import user_router

app=FastAPI()

app.include_router(user_router)

from src.models.user import User
from database.database import SessionLocal

db=SessionLocal()
