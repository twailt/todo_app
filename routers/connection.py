
from database import SessionLocal
from fastapi import Depends, APIRouter, status

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()
