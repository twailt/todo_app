import sys

from fastapi import HTTPException, Request
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional
from starlette import status

import models
from database import engine
from models import Users
from jose import JWTError, jwt
from datetime import datetime, timedelta

import os
from dotenv import load_dotenv
from .connection import get_db

load_dotenv()

sys.path.append('..')

SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
models.Base.metadata.create_all(bind=engine)

class CreateUser(BaseModel):
    username: str
    email: Optional[str]
    first_name: str
    last_name: str
    password: str
    phone_number: Optional[str]


class LoginForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.username: Optional[str] = None
        self.password: Optional[str] = None

    async def create_oauth_form(self):
        form = await self.request.form()
        self.username = form.get('email')
        self.password = form.get('password')


class RegisterForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.email: Optional[str] = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.password2: Optional[str] = None
        self.firstname: Optional[str] = None
        self.lastname: Optional[str] = None

    async def create_register_form(self):
        form = await self.request.form()
        self.email = form.get('email')
        self.username = form.get('username')
        self.password = form.get('password')
        self.password2 = form.get('password2')
        self.firstname = form.get('firstname')
        self.lastname = form.get('lastname')


get_db()

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return bcrypt_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(request: Request):
    try:
        token = request.cookies.get('access_token')
        if token is None:
            return None
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        if username is None or user_id is None:
            print("us")
            raise get_user_exception()
        return {'username': username, 'id': user_id}
    except JWTError:
        raise get_user_exception()


def authenticate_user(db, username: str, password: str):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def get_user_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return credentials_exception


def token_exception():
    token_exception_response = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return token_exception_response