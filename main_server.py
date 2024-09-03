from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import time
import random
import httpx
from pymongo import MongoClient
import mongo_connection

app = FastAPI()
bearer_scheme = HTTPBearer()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to the actual domains you want to allow
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client,db,users_collection,data_collection = mongo_connection.connectToMongoDB()

WORKERS = {}
server_counter = 0
TIMEOUT = 5

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

class PingData(BaseModel):
    server_port: int


@app.post("/ping")
async def ping(data: PingData):
    global server_counter

    server_port = data.server_port
    server_name = next((name for name, info in WORKERS.items() if info["server_port"] == server_port), None)


        
    if server_name:
            WORKERS[server_name] = {
                "server_port": server_port,
                "timestamp": int(time.time())
            }
            print(f"Heartbeat received from authenticated Server {server_name}. Updated timestamp at {time.ctime()}")
    else:
            server_name = f"server{server_counter + 1}"
            WORKERS[server_name] = {
                "server_port": server_port,
                "timestamp": int(time.time())
            }
            server_counter += 1
            print(f"Heartbeat received from new authenticated Server {server_name} at {time.ctime()}")
    
    cleanup_servers()

    return {
        "message": f"Heartbeat received from Server {server_name}.",
        "current_servers": WORKERS 
    }

def cleanup_servers():
    current_time = int(time.time())
    global server_counter

    servers_to_remove = []
    for server_name, server_info in list(WORKERS.items()):
        if current_time - server_info["timestamp"] > TIMEOUT:
            print(f"Server {server_name} timed out and removed from WORKERS.")
            servers_to_remove.append(server_name)

    for server_name in servers_to_remove:
        print(server_name)
        del WORKERS[server_name]
        server_counter -= 1

async def register(user: User):
    try:
        server_name, server_info = random.choice(list(WORKERS.items()))
        server_port = server_info["server_port"]

        async with httpx.AsyncClient() as client:
            response = await client.post(f"http://localhost:{server_port}/register", json=user.dict())
            print(response)
            response.raise_for_status()
            return response.json()

    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to register user: {str(exc)}")
    
async def login(userlogin: UserLogin):
    try:
        server_name, server_info = random.choice(list(WORKERS.items()))
        server_port = server_info["server_port"]

        async with httpx.AsyncClient() as client:
            response = await client.post(f"http://localhost:{server_port}/login", json=userlogin.dict())
            response.raise_for_status()
            return response.json()

    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to login user: {str(exc)}")

async def upload(file: UploadFile = File(...), token: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        server_name, server_info = random.choice(list(WORKERS.items()))
        server_port = server_info["server_port"]
        header = {"Autorization": f"Bearer {token.credentials}"}

        async with httpx.AsyncClient() as client:
            files = {'file': (file.filename, file.file, file.content_type)}

            response = await client.post(f"http://localhost:{server_port}/upload", files=files, headers=header)
            response.raise_for_status()
            return response.json()

    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {str(exc)}")


@app.post("/login")
async def login_ping_worker(userlogin: UserLogin):
    return await login(userlogin)

@app.post("/register")
async def register_ping_worker(userregister: User):
    return await register(userregister)

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), token: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    return await upload(file, token)

@app.get("/workers")
async def workers():
    return WORKERS