from pydantic import BaseModel

class UserSignIn(BaseModel):
    email: str
    password: str