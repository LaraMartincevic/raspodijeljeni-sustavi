from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pymongo.errors import ConnectionFailure, ConfigurationError, ServerSelectionTimeoutError
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from gridfs import GridFS
import io
from fastapi.responses import StreamingResponse
from bson import ObjectId
import logging
import urllib.parse
import httpx
import asyncio
import sys
import mongo_connection

app = FastAPI()  # Instance of FastAPI
security = HTTPBearer()
logging.basicConfig(level=logging.INFO)

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to the actual domains you want to allow
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#load_dotenv()  # Load environment variables from .env file

client,db,users_collection,data_collection = mongo_connection.connectToMongoDB()
    
fs = GridFS(db)

async def ping_main():
    server_port = local_port()
    print(server_port)

    while True:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(f"http://localhost:5000/ping", json={"server_port": server_port})
                print(response.text)
            except httpx.HTTPError as exc:
                print(f"HTTP error occurred: {exc}")
            except Exception as exc:
                print(f"Error occurred: {exc}")
        await asyncio.sleep(3)

def local_port():
    if "--port" in sys.argv: 
        index = sys.argv.index("--port")
        port = int(sys.argv[index + 1])
        print(f"This is port: {port}")
        return port
    raise ValueError("Port not specified in command line arguments")

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(ping_main())

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

@app.post("/register")
async def register_user(user:User):
    return await register(user)

@app.post("/login")
async def login_user(user:UserLogin):
    return await login(user)


async def upload_pdf(file: UploadFile = File(...)):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Invalid file type. Only PDFs are allowed.")
    
    try:
        pdf_content = await file.read()
        pdf_data = {
            "file_name": file.filename,
            "file_content": pdf_content,
            "content_type": file.content_type
        }
        pdf_id = data_collection.insert_one(pdf_data).inserted_id
        return {"file_id": str(pdf_id), "file_name": file.filename}
    except Exception as e:
        logging.error(f"Error uploading PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to upload PDF: {e}")

@app.post("/upload")
async def upload_pdf_to_db(file: UploadFile = File(...), credentials: HTTPAuthorizationCredentials = Depends(verify_token)):
    return await upload_pdf(file)



@app.get("/download/{file_id}")
async def download_pdf(file_id: str, credentials: HTTPAuthorizationCredentials = Depends(verify_token)):
    try:
        file_data = data_collection.find_one({"_id": ObjectId(file_id)})
        if file_data is None:
            raise HTTPException(status_code=404, detail="File not found")
        
        # Encode filename correctly for HTTP headers
        encoded_filename = urllib.parse.quote(file_data['file_name'])
        
        return StreamingResponse(
            io.BytesIO(file_data["file_content"]),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"
            }
        )
    except Exception as e:
        logging.error(f"Error downloading PDF: {e}")
        raise HTTPException(status_code=500, detail=f"File not found: {e}")


@app.on_event("startup")
async def startup_event():
    try:
        logging.info("Pinging MongoDB server...")
        #client.server_info()  # Trigger a call to check if the connection is established
        logging.info("MongoDB connection established successfully.")
    except (ConnectionFailure, ConfigurationError, ServerSelectionTimeoutError) as e:
        logging.error(f"Could not connect to MongoDB: {e}")
        raise HTTPException(status_code=500, detail=f"Could not connect to MongoDB: {e}")