from pydantic import BaseModel

class UserCoin(BaseModel):
    email: str
    coin_id: str