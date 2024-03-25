
from fastapi import Depends, HTTPException, APIRouter, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from starlette import status
import sys
import models
from database import engine
from models import Users
from datetime import timedelta

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse
from .models import authenticate_user, get_db,create_access_token,ACCESS_TOKEN_EXPIRE_MINUTES,get_current_user,get_password_hash
from .forms import LoginForm, RegisterForm

sys.path.append('..')
models.Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory='templates')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



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