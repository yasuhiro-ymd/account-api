from pydantic import BaseModel, constr
from typing import Optional


class UserCreate(BaseModel):
    user_id: constr(min_length=6, max_length=20)
    password: constr(min_length=8, max_length=20)


class UserUpdate(BaseModel):
    nickname: Optional[str] = None
    comment: Optional[str] = None