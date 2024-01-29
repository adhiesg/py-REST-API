# main.py

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from databases import Database
from sqlalchemy import MetaData, create_engine, Table, Column, Integer, String, DateTime, select
from sqlalchemy.sql import func
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

DATABASE_URL = "sqlite:///./users.db"  # Change the database name here

database = Database(DATABASE_URL)
metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("email", String, unique=True, index=True),
    Column("hashed_password", String),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

engine = create_engine(DATABASE_URL)
metadata.create_all(bind=engine)

app = FastAPI()

ALGORITHM = "HS256"

class User(BaseModel):
    email: EmailStr
    password: str
    password_confirmation: str

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

# Signup endpoint
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
    
    if user.password != user.password_confirmation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )

    hashed_password = password_hashing.hash(user.password)
    query = users.insert().values(email=user.email, hashed_password=hashed_password)
    await database.execute(query)
    return {"message": "User signed up successfully"}
