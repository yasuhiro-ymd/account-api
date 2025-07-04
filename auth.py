import base64
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from models import User
from passlib.hash import bcrypt


def get_user_from_auth(auth_header: str | None, db: Session) -> User:
    if not auth_header or not auth_header.startswith("Basic "):
        raise HTTPException(status_code=401, detail="Authentication failed")

    try:
        encoded = auth_header.split(" ")[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        user_id, password = decoded.split(":")
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user or not bcrypt.verify(password, user.password):
            raise HTTPException(status_code=401, detail="Authentication failed")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication failed")