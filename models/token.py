from pydantic import BaseModel, EmailStr

class Token(BaseModel):
    message: str
    token: str
    token_type: str = "bearer"