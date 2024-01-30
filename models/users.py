from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base

class SignUpRequest(BaseModel):
    email: EmailStr
    password: str
    password_confirmation: str

class SignInRequest(BaseModel):
    email: EmailStr
    password: str

class Email(BaseModel):
    email: EmailStr