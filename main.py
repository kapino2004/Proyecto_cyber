import os
import hashlib
import bcrypt 
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from sqlmodel import Field, Session, SQLModel, create_engine, select
from pydantic import BaseModel
from dotenv import load_dotenv


load_dotenv()
PEPPER = os.getenv("PEPPER_SECRET")
if not PEPPER:
    raise ValueError("Error: No se encontró PEPPER_SECRET en el .env")

def get_password_hash(password: str) -> str:
    peppered = password + PEPPER
    sha_hash = hashlib.sha256(peppered.encode('utf-8')).hexdigest()
    
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(sha_hash.encode('utf-8'), salt)
    
    return hashed_bytes.decode('utf-8')

def verify_password(plain_p: str, hashed_p: str) -> bool:
    peppered = plain_p + PEPPER
    sha_hash = hashlib.sha256(peppered.encode('utf-8')).hexdigest()
    
    return bcrypt.checkpw(sha_hash.encode('utf-8'), hashed_p.encode('utf-8'))


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str

class UserCreate(BaseModel):
    username: str
    password: str

engine = create_engine("sqlite:///database.db")

@asynccontextmanager
async def lifespan(app: FastAPI):
    SQLModel.metadata.create_all(engine)
    yield

app = FastAPI(lifespan=lifespan)

@app.post("/register")
def register(user: UserCreate):
    with Session(engine) as session:
        if session.exec(select(User).where(User.username == user.username)).first():
            raise HTTPException(400, "El usuario ya existe")
        
        hashed = get_password_hash(user.password)
        nuevo_usuario = User(username=user.username, hashed_password=hashed)
        session.add(nuevo_usuario)
        session.commit()
        return {"msg": "¡Registrado con éxito!"}

@app.post("/login")
def login(user: UserCreate):
    with Session(engine) as session:
        db_user = session.exec(select(User).where(User.username == user.username)).first()
        if not db_user or not verify_password(user.password, db_user.hashed_password):
            raise HTTPException(401, "Credenciales incorrectas")
        return {"msg": "¡Autenticación exitosa!"}