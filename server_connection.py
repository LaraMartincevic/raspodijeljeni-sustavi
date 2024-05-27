from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pymongo.errors import ConnectionFailure
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from gridfs import GridFS
from io import BytesIO



app = FastAPI()  # Instance of FastAPI
security = HTTPBearer()


load_dotenv()  # Load environment variables from .env file

CONNECTION_STRING = os.getenv("CONNECTION_STRING")  # Get MongoDB connection string from environment
MONGO_DB = os.getenv("MONGO_DB")  # Get the database name from environment

if not CONNECTION_STRING:
    raise ValueError("CONNECTION_STRING environment variable not set")

if not MONGO_DB:
    raise ValueError("Base1 environment variable not set")

        
client = MongoClient(CONNECTION_STRING)
users_collection = None
data_collection = None
db = client[MONGO_DB]  # Get the database
fs = GridFS(db)




async def connection_mongodb():
    global client, db, users_collection, data_collection
    try:
        client.server_info()  # Trigger a call to check if the connection is established
        
        users_collection = db["users"]  # Access collections
        data_collection = db["data"]
    except ConnectionFailure:
        raise HTTPException(status_code=500, detail="Could not connect to MongoDB")

@app.on_event("startup")
async def startup_event():
    await connection_mongodb()
    print("Connected to MongoDB")

@app.on_event("shutdown")
async def shutdown_event():
    if client:
        client.close()
        print("MongoDB connection closed")

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class User(BaseModel):
    name: str
    surname: str
    username: str
    age: int
    adress: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

def get_password_hash(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def create_access_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Token missing")
    return decode_token(token)

async def register(user: User) -> dict:
    existing_user = users_collection.find_one({"$or": [{"email": user.email}, {"username": user.username}]})
    
    if existing_user:
        if existing_user.get("email") == user.email:
            raise HTTPException(status_code=400, detail="Email already exists")
        if existing_user.get("username") == user.username:
            raise HTTPException(status_code=400, detail="Username already exists")
    
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    user_dict["role"] = "user"
    
    try:
        users_collection.insert_one(user_dict)
        return {"message": "User registered successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register user: {str(e)}")


async def login(userlogin: UserLogin) -> dict:
    email = userlogin.email
    password = userlogin.password

    user = users_collection.find_one({"email": email})

    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"email": email, "username": user["username"]}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

async def store_pdf(file: UploadFile, user_email: str) -> str:
    try:
        pdf_data = await file.read()
        pdf_id = fs.put(pdf_data, filename=file.filename, metadata={"uploaded_by": user_email})
        return str(pdf_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload PDF: {str(e)}")

async def retrieve_pdf(pdf_id: str) -> dict:
    try:
        stored_pdf = fs.get(pdf_id)
        return {
            "filename": stored_pdf.filename,
            "content": stored_pdf.read(),
            "content-type": "application/pdf"
        }
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"PDF not found: {str(e)}")


@app.post("/register")
async def register_user(user:User):
    return await register(user)

@app.post("/login")
async def login_user(user:UserLogin):
    return await login(user)


@app.post("/upload_pdf")
async def upload_pdf(file: UploadFile = File(...), token: dict = Depends(verify_token)):
    pdf_id = await store_pdf(file, token["email"])
    return {"message": "PDF uploaded successfully", "pdf_id": pdf_id}

@app.get("/download_pdf/{pdf_id}")
async def download_pdf(pdf_id: str, token: dict = Depends(verify_token)):
    pdf_info = await retrieve_pdf(pdf_id)
    return {
        "filename": pdf_info["filename"],
        "content": pdf_info["content"],
        "content-type": pdf_info["content-type"]
    }


