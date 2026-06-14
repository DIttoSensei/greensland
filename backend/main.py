from fastapi import FastAPI, Depends, HTTPException, Header, Query
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from fastapi.middleware.cors import CORSMiddleware
import random
from io import BytesIO
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import bcrypt
import jwt
import time
import os

app = FastAPI()
API_SECRET_KEY = ""

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = f"sqlite:///{BASE_DIR}/greenlands.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
API_SECRET_KEY = "secure_university_key_2026"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 1. DATABASE SCHEMA UPDATED WITH DEPT AND LEVEL COLUMNS
class ACCOUNTSDB(Base):
    __tablename__ = "ACCOUNTS"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)         
    email = Column(String, nullable=True)
    password = Column(String, index=True)
    usertype = Column(String)

Base.metadata.create_all(bind=engine)
    

class ACCOUNTS(BaseModel):
    id: int
    name: str
    email: EmailStr
    password: str
    usertype: str

    class Config:
        from_attributes = True

class SIGNUPREQUESTS(BaseModel):
    name: str
    email: EmailStr
    password: str
    usertype: str

class LOGINREQUEST(BaseModel):
    email: EmailStr
    password: str


# PASSWORD HASHING FUNCTION
def hash_password(password : str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_pass (password : str, hashed_password : str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def validate_password(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not any(c.isupper() for c in password):
        raise HTTPException(status_code=400, detail="Password must contain an uppercase letter")
    return hash_password(password)


# JWT web token
def generate_token (id : int):
    encoded = jwt.encode ({"id": id, "exp" : int(time.time()) + 18000}, API_SECRET_KEY, algorithm="HS256")
    return encoded

def decode_token (encoded_token : str):
    try:
        decoded = jwt.decode(encoded_token, API_SECRET_KEY, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ENDPOINTS 
# LOGIN AND SIGNUP
@app.post("/signup", status_code=201)
async def signup(data: SIGNUPREQUESTS, db: Session = Depends(get_db)):
    user = db.query(ACCOUNTSDB).filter(ACCOUNTSDB.email == data.email).first()
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")

    if data.usertype == '':
        raise HTTPException(status_code=400, detail="User type is required")

    new_user = ACCOUNTSDB(name=data.name, email=data.email, password=validate_password(data.password), usertype=data.usertype)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {'message': 'User created successfully'}
    

@app.post("/login")
async def login(data : LOGINREQUEST, db: Session = Depends(get_db)):
    user  = db.query(ACCOUNTSDB).filter(ACCOUNTSDB.email == data.email).first()
    if user:
        if verify_pass(data.password, user.password): # type: ignore
            token = generate_token(user.id) # type: ignore
            return {"token": token}
        else:
            raise HTTPException(status_code=400, detail="Incorrect password")
        
    else:
        raise HTTPException(status_code=400, detail="Email not found")


def get_current_user(authorization: str = Header(...), db: Session = Depends(get_db)):
    token = authorization.split(" ")[1]
    payload = decode_token(token)
    payload_id = payload['id']
    user = db.query(ACCOUNTSDB).filter(ACCOUNTSDB.id == payload_id).first()
    if user:
        return user
    else:
        raise HTTPException(status_code=401, detail="User not found")