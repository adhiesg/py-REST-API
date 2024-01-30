# main.py

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer
from databases import Database
from sqlalchemy import MetaData, create_engine, Table, Column, Integer, String, DateTime, select, ForeignKey, Float
from sqlalchemy.sql import func
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from models.users import SignUpRequest, SignInRequest, Email
from models.token import Token
from models.coins import UserCoin

import jwt
import httpx

#no need env for easier testing
DATABASE_URL = "sqlite:///./test2.db"  
SECRET_KEY = "secR3t_Keyyy"

database = Database(DATABASE_URL)
metadata = MetaData()
http_client = httpx.AsyncClient()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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
    Column("coin_price_idr", Float),

)
engine = create_engine(DATABASE_URL)
metadata.create_all(bind=engine)

app = FastAPI()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1

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

# Function to validate user
async def validate_user(email: str) -> dict:
    # Fetch user data from the database
    user_query = select([users.c.jwt_token]).where(users.c.email == email)
    user_record = await database.fetch_one(user_query)

    # Validate if the user exists
    if user_record is None:
        raise HTTPException(status_code=404, detail="Not Authorized")

    # Validate the JWT token
    try:
        payload = jwt.decode(user_record['jwt_token'], SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
# Function to convert usd to idr from open.er-api exchange rate
async def convert_usd_to_idr(amount_usd: float) -> float:
    try:
        # Make a request to get the latest exchange rates
        async with httpx.AsyncClient() as client:
            response = await client.get("https://open.er-api.com/v6/latest/USD")
            response.raise_for_status()
            data = response.json()

        # Extract the exchange rate for USD to IDR
        exchange_rate_usd_to_idr = data["rates"]["IDR"]

        # Convert the amount from USD to IDR
        amount_idr = amount_usd * exchange_rate_usd_to_idr

        return amount_idr

    except httpx.HTTPError as e:
        # Handle HTTP errors
        raise HTTPException(status_code=500, detail=f"Error fetching exchange rates: {e}")
    except (KeyError, ValueError) as e:
        # Handle JSON parsing errors
        raise HTTPException(status_code=500, detail=f"Error parsing exchange rate data: {e}")
    
# Function to fetch the USD amount for a coin from the CoinCap API
async def fetch_coin_price_usd(coin_name: str) -> float:
    try:
        # Make a request to get the latest information for the specified coin
        async with httpx.AsyncClient() as client:
            response = await client.get(f"https://api.coincap.io/v2/assets/{coin_name}")
            response.raise_for_status()
            data = response.json()

        # Extract the price in USD from the response
        amount_usd = float(data["data"]["priceUsd"])

        return amount_usd

    except httpx.HTTPError as e:
        # Handle HTTP errors
        raise HTTPException(status_code=500, detail=f"Error fetching coin price from CoinCap API: {e}")
    except (KeyError, ValueError) as e:
        # Handle JSON parsing errors
        raise HTTPException(status_code=500, detail=f"Error parsing coin price data from CoinCap API: {e}")
    

# signup endpoint
@app.post("/signup")
async def signup(form_data: SignUpRequest):

    # Check if the user already exists
    user_exists_query = select([users]).where(users.c.email == form_data.email)
    existing_user = await database.fetch_one(user_exists_query)

    if existing_user:
        raise HTTPException(status_code=400, detail="Email is already registered")

    # Hash the password before storing it in the database
    hashed_password = password_hashing.hash(form_data.password)

    # Insert the new user into the users table
    signup_query = users.insert().values(email=form_data.email, hashed_password=hashed_password)
    user_id = await database.execute(signup_query)

    return {"message": "sign up successful"}

# signin endpoint
# since the jwt is not handled in client side, we need to store it in database
@app.post("/signin", response_model=Token)
async def signin(form_data: SignInRequest):
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
async def signout(form_data: Email):
    email = form_data.email
    if not email:
        raise HTTPException(status_code=400, detail="Email is required in the request body")

    update_query = users.update().where(users.c.email == email).values(jwt_token=None)
    await database.execute(update_query)

    return {"message": "User signed out successfully"}


# token list endpoint to get the list of tokens from coincap
# only authenticated users can access this endpoint
@app.post("/tokenlist")
async def token_list(form_data: Email):
    email = form_data.email
    if not email:
        raise HTTPException(status_code=400, detail="Email is required in the request body")
    try:
        payload = await validate_user(email)

        # fetch data from extenal API
        coin_api_url = "https://api.coincap.io/v2/assets"
        response = await http_client.get(coin_api_url)

        if response.status_code == 200:
            return response.json()
        else:
            raise HTTPException(status_code=response.status_code, detail="Error fetching token list")
    except HTTPException as e:
        return {"error": str(e)}
    
    

@app.get("/usertrackedcoins")
async def user_tracked_coins(form_data: Email):
    email = form_data.email
    if not email:
        raise HTTPException(status_code=400, detail="Email is required in the request body")
    try:
        payload = await validate_user(email)
        
        # Fetch the list of tracked coins for the user
        tracked_coins_query = select([tracked_coins]).where(tracked_coins.c.user_email == email)
        tracked_coins_list = await database.fetch_all(tracked_coins_query)

        if not tracked_coins_list:
            raise HTTPException(status_code=404, detail=f"No tracked coins")

        user_tracked_coins = [{"coin_name": coin["coin_name"], "coin_price_idr": coin["coin_price_idr"]} for coin in tracked_coins_list]

        return {"user_tracked_coins": user_tracked_coins}
    
    except HTTPException as e:
        return {"error": str(e)}

    

@app.post("/addcoin")
async def add_coin(form_data: UserCoin):
    email = form_data.email
    coin_name = form_data.coin_name

    if not email or not coin_name:
        raise HTTPException(status_code=400, detail="Email and coin_name are required in the request body")

   # Validate user
    try:
        payload = await validate_user(email)

        # Check if the coin is already tracked by the user
        tracked_coin_query = select([tracked_coins]).where(
            (tracked_coins.c.user_email == email) & (tracked_coins.c.coin_name == coin_name)
        )
        existing_tracked_coin = await database.fetch_one(tracked_coin_query)

        if existing_tracked_coin:
            raise HTTPException(status_code=400, detail=f"Coin {coin_name} is already being tracked by the user")

        # Fetch the amount in USD for the specified coin from the CoinCap API
        amount_usd = await fetch_coin_price_usd(coin_name)

        # Convert USD to IDR using the exchange rate
        amount_idr = await convert_usd_to_idr(amount_usd)

        # Add the coin to the user's tracker with the converted amount in IDR
        add_coin_query = tracked_coins.insert().values(
            user_email=email,
            coin_name=coin_name,
            coin_price_idr=amount_idr,
        )
        await database.execute(add_coin_query)

        return {"message": f"{coin_name} added to tracker for user {email}"}
    except HTTPException as e:
        return {"error": str(e)}
    
@app.delete("/removecoin")
async def remove_coin(form_data: UserCoin):
    email = form_data.email
    coin_name = form_data.coin_name

    if not email or not coin_name:
        raise HTTPException(status_code=400, detail="Email and coin_name are required in the request body")
    
    try:
        payload = await validate_user(email)

        # Check if the coin is tracked by the user
        tracked_coin_query = select([tracked_coins]).where(
            (tracked_coins.c.user_email == email) & (tracked_coins.c.coin_name == coin_name)
        )
        existing_tracked_coin = await database.fetch_one(tracked_coin_query)

        if existing_tracked_coin is None:
            raise HTTPException(status_code=404, detail=f"Coin {coin_name} is not tracked by the user")

        # Remove the coin from the user's tracked list
        remove_coin_query = tracked_coins.delete().where(
            (tracked_coins.c.user_email == email) & (tracked_coins.c.coin_name == coin_name)
        )
        await database.execute(remove_coin_query)

        return {"message": f"Coin {coin_name} removed from tracker for user {email}"}

    except HTTPException as e:
        return {"error": str(e)}