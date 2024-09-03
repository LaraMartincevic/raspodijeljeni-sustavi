import os
from dotenv import load_dotenv
from pymongo import MongoClient


load_dotenv()  # Load environment variables from .env file

CONNECTION_STRING = os.getenv("CONNECTION_STRING")
  # Get MongoDB connection string from environment
MONGO_DB = os.getenv("MONGO_DB")

if not CONNECTION_STRING:
    raise ValueError("CONNECTION_STRING environment variable not set")

if not MONGO_DB:
    raise ValueError("Base1 environment variable not set")

def connectToMongoDB():
    client = MongoClient(CONNECTION_STRING)
    db = client[MONGO_DB]  # Get the database
    users_collection = db["users"]  # Access collections
    data_collection = db["data"]
    return client,db,users_collection,data_collection