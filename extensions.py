import os

from flask_pymongo import PyMongo
from pymongo import MongoClient

MONGODB_URI = os.environ.get("MONGODB_URI")

mongo = PyMongo()


def connect_mongo(dbname: str):
    client = MongoClient(MONGODB_URI)
    db = client["step_training"]
    collection = db[dbname]
    return collection
