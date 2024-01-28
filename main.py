# main.py

from fastapi import FastAPI
from databases import Database

DATABASE_URL = "sqlite:///./users.db"

database = Database(DATABASE_URL)

app = FastAPI()
@app.on_event("startup")
async def startup():
    await database.connect()
    print("Connected to the users database")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    print("Disconnected from the users database")
