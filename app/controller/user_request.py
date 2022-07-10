import datetime
import json

from flask import Response

from app.controller import JSONEncoder

from .user_controller import collection_users


def get_users():
    users = [col for col in collection_users.find()]
    return Response(JSONEncoder().encode(users), mimetype="application/json")


def get_users_array():
    return [col for col in collection_users.find()]


def get_user_by_email(email: str):
    return [col for col in collection_users.find({"email": email})][0]


def set_datetime_login(email: str):
    collection_users.update_one(
        {"email": email}, {"$set": {"dateLogin": datetime.datetime.now()}}
    )


def check_exists_by_email(email: str):
    return (
        True
        if [col["_id"] for col in collection_users.find({"email": email})]
        else False
    )


def create_user(user):
    collection_users.insert_one(user)
