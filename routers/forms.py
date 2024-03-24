from fastapi import Request
from typing import Optional


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