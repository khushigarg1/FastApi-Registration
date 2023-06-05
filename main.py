

from time import strftime
from fastapi import FastAPI, Depends, HTTPException, status, Response, Security
from fastapi.security import APIKeyHeader

from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from os import getenv
from jose import JWTError, jwt
from sqlalchemy import false
from sqlalchemy.orm import Session
from database import get_db, engine
import models
from schemas import ApiKeyRequestForm, UserCreate, UserResponse,UserCreateResponse
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
import secrets
import oauth2
from utils import encrypt_api_key,decrypt_api_key
import pytz

models.Base.metadata.create_all(bind=engine)
app = FastAPI()

@app.get("/") 
def root():
   
    return {"message": "You called a ginnie, i'll grant you 3 wishes!!!"}

#---------------------------------REGISTER---------------------------------

@app.post("/register",status_code=status.HTTP_201_CREATED,response_model=UserCreateResponse)
def register(user: UserCreate, db:Session = Depends(get_db)  ):
    print(encrypt_api_key("hello"))
    print(encrypt_api_key("hello"))
    checkUserExists = db.query(models.User).filter(models.User.email == user.email).first()
    if checkUserExists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail=f"User already exists with email: {user.email}")
    apikey = ""
    ok = True
    print("here")
    while ok:
        print("here")
        apikey = secrets.token_hex(5)
        # hashed_apikey = apikey
        hashed_apikey = encrypt_api_key(apikey)
        check = db.query(models.User).filter(models.User.appikey == hashed_apikey).first()
        if check is None:
            ok = False

    new_user = models.User(**user.dict(),appikey=hashed_apikey)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"name":new_user.name,"email":new_user.email,"apikey":apikey}

#------------------AUTHENTICATE--------------------------------------
# @app.get("/timeelapsed/{id}")
def get_time(user_created_at):
    # user = db.query(models.User).filter(models.User.id == id).first()
    # created_at_datetime = datetime.strptime(user.created_at, "%Y-%m-%d %H:%M:%S")
    # datetime_obj = datetime.fromisoformat(user.created_at)
    # print(strftime(user.created_at))
    # print(created_at)
    # print(type(user.created_at))
    # user_created_at  = user.created_at
    timezone_offset  = user_created_at.utcoffset()
    print(timezone_offset)
    current_time = datetime.now() 
    # user_created_at = user_created_at.replace(tzinfo=timezone_offset)
    # current_time = datetime.now(timezone_offset)
    offset_aware_time = current_time.replace(tzinfo=timezone(timezone_offset))
    time_difference = offset_aware_time - user_created_at
    print(time_difference)
    # # Access the elapsed time components
    # # days = time_difference.days
    return time_difference.days


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
@app.post("/user/authenticate")
def authenticate(response: Response,api_key: str = Security(api_key_header), db:Session = Depends(get_db)):
    
    hashed_api_key = encrypt_api_key(api_key)
    user = db.query(models.User).filter(models.User.appikey == hashed_api_key).first()

    if user is None:
        raise HTTPException(status_code=400, detail="Invalid api_key")
    if get_time(user.created_at) > 365:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail=f"The user has expired")
    access_token = oauth2.create_access_token(data = {"user_id": user.id }) 
    print("created : ",access_token)
    response.set_cookie(key="access_token", value=access_token, httponly=True)   
    return {"message": "Authentication successful"}
    # return {"access_token": access_token, "token_type": "bearer"}
    # hashed_api_key = user.get("api_key")
    # if verify_password(api_key_cookie, hashed_api_key):

#-------------------GET DATA------------------------------

@app.get("/getUserData",response_model=UserResponse)
def get_user_data(current_user = Depends(oauth2.get_current_user), db:Session = Depends(get_db)):
    # user = users_collection.find_one({"username": username})
    user = db.query(models.User).filter(models.User.id == current_user.id).first()

    if user:
        return user

    raise HTTPException(status_code=400, detail="User does not exist")
