from pydantic import BaseModel,EmailStr
from typing import Optional


class RegisterUserSchema(BaseModel):
    username: str
    email: EmailStr
    password: str
    
class GetAllUserSchema(BaseModel):
    id:str
    username:str
    email:str
    password:str
    
class UpdateUserSchema(BaseModel):
    username:Optional[str]=None
    email:Optional[EmailStr]=None
    password:Optional[str]=None
    
class ForgetPasswordSchema(BaseModel):
    new_password:str
    confirm_password:str
    
class ResetPasswordSchema(BaseModel):
    old_password:str
    new_password:str
    confirm_password:str
    
    