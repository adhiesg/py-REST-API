# main.py

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer
from databases import Database
from sqlalchemy import MetaData, create_engine, Table, Column, Integer, String, DateTime, select, ForeignKey, Float
from sqlalchemy.sql import func
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta

import jwt
import httpx

#no need env for easier testing
DATABASE_URL = "sqlite:///./test1.db"  
SECRET_KEY = "secR3t_Keyyy"

database = Database(DATABASE_URL)
metadata = MetaData()
http_client = httpx.AsyncClient()

users = Table(
    "users",
    metadata,
    Column("email", String, primary_key=True, index=True),  # Using email as the primary key
    Column("hashed_password", String),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Column("jwt_token", String, nullable=True),
)

tracked_coins = Table(
    "tracked_coins",
    metadata,
    Column("user_email", ForeignKey("users.email"), primary_key=True, index=True),  # Foreign key referencing the users table
    Column("coin_name", String, primary_key=True),
    Column("coin_price_usd", Float),
    # Add more columns as needed, such as date_added, etc.
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

    # Check if the user already exists
    user_exists_query = select([users]).where(users.c.email == user.email)
    existing_user = await database.fetch_one(user_exists_query)

    if existing_user:
        raise HTTPException(status_code=400, detail="Email is already registered")

    # Hash the password before storing it in the database
    hashed_password = password_hashing.hash(user.password)

    # Insert the new user into the users table
    signup_query = users.insert().values(email=user.email, hashed_password=hashed_password)
    user_id = await database.execute(signup_query)

    return {"message": "sign up successful"}

# signin endpoint
# since the jwt is not handled in client side, we need to store it in database
@app.post("/signin", response_model=Token)
async def signin(form_data: Signin):
    # check if the user exists in the database
    query_check_user = select([users]).where(users.c.email == form_data.email)
    user_record = await database.fetch_one(query_check_user)

    if user_record and password_hashing.verify(form_data.password, user_record['hashed_password']):
        # generate JWT token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        expiration = datetime.utcnow() + access_token_expires
        to_encode = {"sub": form_data.email, "exp": expiration}
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

        # Store the JWT token in the users database
        update_query = users.update().where(users.c.email == form_data.email).values(jwt_token=encoded_jwt)
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


# token list endpoint to get the list of tokens from coincap
# only authenticated users can access this endpoint
@app.post("/tokenList")
async def token_list(request_data: dict):
    email = request_data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    # Fetch the JWT token from the user's record
    user_query = select([users.c.jwt_token]).where(users.c.email == email)
    user_record = await database.fetch_one(user_query)

    if not user_record or user_record['jwt_token'] is None:
        raise HTTPException(status_code=404, detail=f"Not Authorized")

    # Validate the JWT token
    try:
        payload = jwt.decode(user_record['jwt_token'], SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Call the external API using the JWT token
    coin_api_url = "https://api.coincap.io/v2/assets"
    response = await http_client.get(coin_api_url)

    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=response.status_code, detail="Error fetching token list")

@app.get("/userTrackedCoins")
async def user_tracked_coins(request_data: dict):
    email = request_data.get("email")
    # Check if the user with the provided email exists
    user_query = select([users]).where(users.c.email == email)
    user = await database.fetch_one(user_query)

    if user is None:
        raise HTTPException(status_code=404, detail=f"User not found")

    # Fetch the list of tracked coins for the user
    tracked_coins_query = select([tracked_coins]).where(tracked_coins.c.user_email == email)
    tracked_coins_list = await database.fetch_all(tracked_coins_query)

    if not tracked_coins_list:
        raise HTTPException(status_code=404, detail=f"No tracked coins")

    user_tracked_coins = [{"coin_name": coin["coin_name"], "coin_price_usd": coin["coin_price_usd"]} for coin in tracked_coins_list]

    return {"user_tracked_coins": user_tracked_coins}