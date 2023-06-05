
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import Depends, Request, status, HTTPException
import schemas,database,models
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from config import settings
#we need:
#secret key
#algo
#expiration time: time for which the token is valid
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SECRET_KEY = settings.secret_key
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes

def create_access_token(data: dict):
    print("create access token")
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str, credentials_exception):
    print("auth : ",token)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms={ALGORITHM})

        id = payload.get("user_id")
        # print(payload)
        if id is None:
            raise credentials_exception
        token_data = schemas.TokenData(id = id)
    except JWTError:
        raise credentials_exception
    return token_data

def get_current_user(request: Request,db: Session = Depends(database.get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
         detail=f"Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    token = request.cookies.get("access_token")
    print("get_current_user",token)
    if token is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token. Please login")
    token_data = verify_access_token(token, credentials_exception)

    user = db.query(models.User).filter(models.User.id == token_data.id).first()
    return user