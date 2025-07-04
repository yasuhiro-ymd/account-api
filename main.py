from fastapi import FastAPI, Depends, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.hash import bcrypt
import base64

app = FastAPI()
security = HTTPBasic()

# ----------------------------
# Database setup
# ----------------------------
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    user_id = Column(String, primary_key=True, index=True)
    password = Column(String, nullable=False)
    nickname = Column(String, default="")
    comment = Column(String, default="")

Base.metadata.create_all(bind=engine)

# ----------------------------
# Pydantic schemas
# ----------------------------
class SignupRequest(BaseModel):
    user_id: str
    password: str

class UpdateUserRequest(BaseModel):
    nickname: str
    comment: str

# ----------------------------
# Exception handlers
# ----------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"message": "Account creation failed", "cause": "Required user_id and password"},
    )

# ----------------------------
# Utilities
# ----------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(credentials: HTTPBasicCredentials = Depends(security), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == credentials.username).first()
    if not user or not bcrypt.verify(credentials.password, user.password):
        raise JSONResponse(status_code=401, content={"message": "Authentication failed"})
    return user

# ----------------------------
# Routes
# ----------------------------
@app.post("/signup")
def signup(data: SignupRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.user_id == data.user_id).first()
    if existing:
        return JSONResponse(status_code=409, content={"message": "Account already exists"})

    user = User(
        user_id=data.user_id,
        password=bcrypt.hash(data.password)
    )
    db.add(user)
    db.commit()
    return {"message": "Account successfully created"}

@app.get("/users/{user_id}")
def get_user(user_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        return JSONResponse(status_code=404, content={"message": "No user found"})
    return {
        "user_id": user.user_id,
        "nickname": user.nickname,
        "comment": user.comment
    }

@app.patch("/users/{user_id}")
def update_user(user_id: str, update: UpdateUserRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.user_id != user_id:
        return JSONResponse(status_code=403, content={"message": "Forbidden"})

    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        return JSONResponse(status_code=404, content={"message": "No user found"})

    user.nickname = update.nickname
    user.comment = update.comment
    db.commit()
    return {"message": "User updated"}

@app.post("/close")
def delete_user(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == current_user.user_id).first()
    if user:
        db.delete(user)
        db.commit()
    return {"message": "Account and user successfully removed"}

# ----------------------------
# Root for 404 fallback
# ----------------------------
@app.get("/")
def root():
    raise HTTPException(status_code=404, detail="Not Found")