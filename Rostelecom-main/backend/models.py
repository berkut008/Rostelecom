from pydantic import BaseModel

class UserRegister(BaseModel):
    login: str
    full_name: str
    password: str

class UserLogin(BaseModel):
    login: str
    password: str

class AdminCreateUser(BaseModel):
    login: str
    full_name: str
    password: str