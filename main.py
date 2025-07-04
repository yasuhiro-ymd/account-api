from fastapi import FastAPI, Request, Header, HTTPException, status, Depends
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import User
from schemas import UserCreate, UserUpdate
from auth import get_user_from_auth
from passlib.hash import bcrypt
import re

from models import Base
Base.metadata.create_all(bind=engine)

app = FastAPI()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def is_valid_user_id(user_id: str):
    return re.fullmatch(r'[A-Za-z0-9]{6,20}', user_id)


def is_valid_password(password: str):
    return re.fullmatch(r'[!-~]{8,20}', password)  # ASCII 33-126


@app.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    if not user.user_id or not user.password:
        raise HTTPException(status_code=400, detail={
            "message": "Account creation failed",
            "cause": "Required user_id and password"
        })
    if not is_valid_user_id(user.user_id) or not is_valid_password(user.password):
        raise HTTPException(status_code=400, detail={
            "message": "Account creation failed",
            "cause": "Incorrect character pattern"
        })
    existing = db.query(User).filter(User.user_id == user.user_id).first()
    if existing:
        raise HTTPException(status_code=400, detail={
            "message": "Account creation failed",
            "cause": "Already same user_id is used"
        })
    new_user = User(
        user_id=user.user_id,
        password=bcrypt.hash(user.password),
        nickname=user.user_id
    )
    db.add(new_user)
    db.commit()
    return {
        "message": "User details by user_id",
        "user": {
            "user_id": new_user.user_id,
            "nickname": new_user.nickname
        }
    }


@app.get("/users/{user_id}")
def get_user(user_id: str, authorization: str = Header(None), db: Session = Depends(get_db)):
    user = get_user_from_auth(authorization, db)
    if user.user_id != user_id:
        raise HTTPException(status_code=403, detail={"message": "No permission for this operation"})
    if not user:
        raise HTTPException(status_code=404, detail={"message": "No user found"})
    user_data = {
        "user_id": user.user_id,
        "nickname": user.nickname if user.nickname else user.user_id
    }
    if user.comment:
        user_data["comment"] = user.comment
    return {
        "message": "User details by user_id",
        "user": user_data
    }


@app.patch("/users/{user_id}")
def update_user(user_id: str, updates: UserUpdate, authorization: str = Header(None), db: Session = Depends(get_db)):
    user = get_user_from_auth(authorization, db)
    if user.user_id != user_id:
        raise HTTPException(status_code=403, detail={"message": "No permission for this operation"})

    if updates.nickname is None and updates.comment is None:
        raise HTTPException(status_code=400, detail={
            "message": "User updation failed",
            "cause": "Required nickname or comment"
        })

    if updates.nickname is not None:
        if len(updates.nickname) > 30:
            raise HTTPException(status_code=400, detail={
                "message": "User updation failed",
                "cause": "Invalid nickname or comment"
            })
        user.nickname = updates.nickname if updates.nickname else user.user_id

    if updates.comment is not None:
        if len(updates.comment) > 100:
            raise HTTPException(status_code=400, detail={
                "message": "User updation failed",
                "cause": "Invalid nickname or comment"
            })
        user.comment = updates.comment if updates.comment else ""

    db.commit()
    return {
        "message": "User successfully updated",
        "user": {
            "nickname": user.nickname,
            "comment": user.comment
        }
    }


@app.post("/close")
def delete_user(authorization: str = Header(None), db: Session = Depends(get_db)):
    user = get_user_from_auth(authorization, db)
    db.delete(user)
    db.commit()
    return {
        "message": "Account and user successfully removed"
    }