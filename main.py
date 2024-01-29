# main.py

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from databases import Database
from sqlalchemy import MetaData, create_engine, Table, Column, Integer, String, DateTime, select
from sqlalchemy.sql import func
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta

import jwt

#no need env for easier testing
DATABASE_URL = "sqlite:///./test1.db"  
SECRET_KEY = "secR3t_Keyyy"

database = Database(DATABASE_URL)
metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("email", String, unique=True, index=True),
    Column("hashed_password", String),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Column("jwt_token", String, nullable=True)
)

engine = create_engine(DATABASE_URL)
metadata.create_all(bind=engine)

app = FastAPI()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class User(BaseModel):
    email: EmailStr
    password: str
    password_confirmation: str

class Signin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    message: str
    token: str
    token_type: str = "bearer"

# Password hashing method
password_hashing = CryptContext(schemes=["bcrypt"], deprecated="auto")

# for db init and shutdown
@app.on_event("startup")
async def startup():
    await database.connect()
    print("Connected to the database")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    print("Disconnected from the database")

# signup endpoint
@app.post("/signup")
async def signup(user: User):

    # check if email is exist in db
    query_check_email = select([users.c.id]).where(users.c.email == user.email)
    existing_user = await database.fetch_one(query_check_email)

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    
    # check if passwords match
    if user.password != user.password_confirmation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )

    hashed_password = password_hashing.hash(user.password)
    query = users.insert().values(email=user.email, hashed_password=hashed_password)
    await database.execute(query)
    return {"message": "User signed up successfully"}

# signin endpoint
# since the jwt is not handled in client side, we need to store it in database
@app.post("/signin", response_model=Token)
async def signin(form_data: Signin):
    # check if the user exists in the database
    query_check_user = select([users.c.id, users.c.hashed_password]).where(users.c.email == form_data.email)
    user_record = await database.fetch_one(query_check_user)

    if user_record and password_hashing.verify(form_data.password, user_record['hashed_password']):
        # generate JWT token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        expiration = datetime.utcnow() + access_token_expires
        to_encode = {"sub": form_data.email, "exp": expiration}
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

        # Store the JWT token in the users database
        update_query = users.update().where(users.c.id == user_record['id']).values(jwt_token=encoded_jwt)
        await database.execute(update_query)

        return {"message": "User signed in successfully", "token": encoded_jwt ,"token_type": "bearer"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

# signout endpoint 
# remove the jwt from the database
@app.post("/signout")
async def signout(request_data: dict):
    email = request_data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required in the request body")

    update_query = users.update().where(users.c.email == email).values(jwt_token=None)
    await database.execute(update_query)

    return {"message": "User signed out successfully"}