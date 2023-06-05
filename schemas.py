import email
from secrets import token_bytes
from fastapi import Form
from pydantic import BaseModel, EmailStr, conint
from datetime import datetime
from typing import Optional

from fastapi.security.oauth2 import OAuth2PasswordRequestForm


#---------------------USER--------------------------------------------------------
class UserCreate(BaseModel):
    email: EmailStr
    name: str
    # password: str

class UserCreateResponse(BaseModel):
    # id: int
    name:str
    email: EmailStr
    apikey:str
    # created_at: datetime
    class Config:
        orm_mode = True
class UserResponse(BaseModel):
    # id: int
    name:str
    email: EmailStr
    # appikey:str
    # created_at: datetime
    class Config:
        orm_mode = True

class ApiKeyRequestForm():
    api_key: str = Form()

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
class TokenData(BaseModel):
    id: Optional[str] = None
