from pydantic import BaseModel, ValidationError, constr, conint, validator
from app.models import User

class UserSchema(BaseModel):
    name: str
    username:str    
    password_hash: str
    email: str

    # @validator('username')
    # def validate_username(cls, value):
    #     breakpoint()
    #     if User.query.filter_by(username=value).first():
            
    #         raise ValueError("User name is already present")
    #     return value
        # if User.query.filter_by(username=None):
        #     raise ValueError("Please enter Username")
        # return value

    class Config:
        from_attributes = True