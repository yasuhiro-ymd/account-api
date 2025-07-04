from sqlalchemy import Column, String
from database import Base

class User(Base):
    __tablename__ = "users"

    user_id = Column(String, primary_key=True, index=True)
    password = Column(String)
    nickname = Column(String, default="")
    comment = Column(String, default="")