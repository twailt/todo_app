
from fastapi import Depends, HTTPException, APIRouter, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from starlette import status
import sys
import models
from database import engine
from models import Users

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse
from .models import authenticate_user, get_db,create_access_token,ACCESS_TOKEN_EXPIRE_MINUTES,get_current_user,get_password_hash
from .forms import LoginForm, RegisterForm, ResetForm, NewPasswordForm
from sendgrid.helpers.mail import Mail
from pydantic import BaseModel
from sendgrid import SendGridAPIClient
from jose import JWTError, jwt
import os
from datetime import datetime, timedelta
import models

sys.path.append('..')
models.Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory='templates')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = os.getenv('SECRET_KEY')
SENDGRID_KEY = os.getenv('SENDGRID_KEY')
ALGORITHM = "HS256"

router = APIRouter(
    prefix='/routes',
    tags=['Routes'],
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            'user': 'Not authorized'
        }
    }
)

@router.post('/token')
async def login_for_access_token(response: Response,
                                 form_data: OAuth2PasswordRequestForm = Depends(),
                                 db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)

    if not user:
        return False  # token_exception()

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, 'id': user.id},
        expires_delta=access_token_expires)

    response.set_cookie(key='access_token', value=access_token, httponly=True)

    return True  # {"access_token": access_token, "token_type": "bearer"}


@router.get('/', response_class=HTMLResponse)
async def auth_page(request: Request):
    user = await get_current_user(request)
    if user is not None:
        return RedirectResponse(url='/', status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse('user/login.html', {'request': request})


@router.post('/', response_class=HTMLResponse)
async def login(request: Request, db: Session = Depends(get_db)):
    try:
        form = LoginForm(request)
        await form.create_oauth_form()
        response = RedirectResponse(url='/', status_code=status.HTTP_302_FOUND)
        validate_user_cookie = await login_for_access_token(response=response, form_data=form, db=db)

        if not validate_user_cookie:
            msg = 'Incorrect Username or Password'
            return templates.TemplateResponse('user/login.html', {'request': request, 'msg': msg})
        return response
    except HTTPException:
        msg = 'Unknown Error'
        return templates.TemplateResponse('user/login.html', {'request': request, 'msg': msg})


@router.get('/logout', response_class=HTMLResponse)
async def logout(request: Request):
    msg = 'Logout Successful'
    response = templates.TemplateResponse('user/login.html', {'request': request, 'msg': msg})
    response.delete_cookie(key='access_token')
    return response


@router.get('/register', response_class=HTMLResponse)
async def register_page(request: Request):
    user = await get_current_user(request)
    if user is not None:
        return RedirectResponse(url='/', status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse('user/register.html', {'request': request})


@router.post('/register')
async def create_new_user(request: Request, db: Session = Depends(get_db)):
    form = RegisterForm(request)
    await form.create_register_form()
    user = Users()
    user.email = form.email
    user.username = form.username
    user.first_name = form.firstname
    user.last_name = form.lastname
    user.hashed_password = get_password_hash(form.password)
    user.is_active = True



    db.add(user)
    db.commit()

    msg = 'User successfully created'
    response = templates.TemplateResponse('user/login.html', {'request': request, 'msg': msg})
    return response

@router.get('/reset', response_class=HTMLResponse)
async def reset_page(request: Request):
    user = await get_current_user(request)
    if user is not None:
        return RedirectResponse(url='/', status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse('user/Reset_Password.html', {'request': request})

@router.post('/reset', response_class=HTMLResponse)
async def reset_password(request: Request, db: Session = Depends(get_db)):
    form = ResetForm(request)
    await form.create_reset_form()

    user_model = db.query(models.Users).filter(models.Users.email == form.email).first()
    if user_model is None:
        return 'Invalid User'

    # Send password reset email
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_model.username, 'id': user_model.id},
        expires_delta=access_token_expires)

    print(f'Click <a href="http://127.0.0.1:8000/routes/new_password/{access_token}">here</a> to reset your password.')

    sendgrid_client = SendGridAPIClient(api_key=SENDGRID_KEY)
    message = Mail(
        from_email='bohdankozin@gmail.com',
        to_emails=form.email,
        subject='Reset your password',
        html_content=f'Click <a href="http://127.0.0.1:8000/routes/new_password/{access_token}">here</a> to reset your password.'
    )
    try:
        response = sendgrid_client.send(message)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    return RedirectResponse(url='/', status_code=status.HTTP_302_FOUND)


@router.get('/new_password/{token}', response_class=HTMLResponse)
async def new_password_page(token: str, request: Request):
    return templates.TemplateResponse('user/new_password.html', {'request': request, 'token': token})

@router.post('/new_password/{token}', response_class=HTMLResponse)
async def new_password_page(token: str, request: Request, db: Session = Depends(get_db)):
    form = NewPasswordForm(request)
    await form.create_new_password_form()

    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id: int = payload.get("id")
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if user is None:
        return RedirectResponse(url='/', status_code=status.HTTP_302_FOUND)

    user.hashed_password = get_password_hash(form.password)

    db.commit()
    db.refresh(user)
    return RedirectResponse(url='/', status_code=status.HTTP_302_FOUND)

# router = APIRouter()

# @router.post("/reset_password")  # Оновлений маршрут
# async def reset_password(email: str):
#     # Логіка скидання пароля через SendGrid
#     # Після успішного відправлення листа, поверніть сторінку підтвердження
#     return {"message": "Password reset email sent successfully"}



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





