import datetime
import os

from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash

from app.controller import response
from app.model.user_model import User
from extensions import connect_mongo

user_bp = Blueprint("user", __name__, url_prefix="/api/user")
SECRET_KEY = os.environ.get("SECRET_KEY")

collection_users = connect_mongo("users")


@user_bp.route("/register", methods=["POST"])
def register_user():
    from app.jwt.auth import authenticate_user

    req = request.get_json()
    find = [col["_id"] for col in collection_users.find({"email": req["email"]})]
    if not find:
        req["password"] = generate_password_hash(req["password"], method=SECRET_KEY)
        user = User(
            **req,
            enabled=True,
            google=False,
            dateInit=datetime.datetime.now(),
            dateLogin=datetime.datetime.now(),
            admin=False,
        )
        collection_users.insert_one(user)
        access_token, refresh_token = authenticate_user(req["email"], req["password"])
        return response(
            200,
            request.url,
            "Create Successful",
            payload={"accessToken": access_token, "refreshToken": refresh_token},
        )
    return response(401, request.url, "Email already exists -> " + req["email"])


@user_bp.route("/get_users", methods=["GET"])
def get_users():
    try:

        import json

        from app.controller import JSONEncoder

        from .user_request import get_users, get_users_array

        users = []
        for user in get_users_array():
            del user["password"]
            user["dateLogin"] = str(user["dateLogin"])
            user["dateInit"] = str(user["dateInit"])
            users.append(user)
        return response(status=200, name=request.url, description="", payload=users)
    except Exception as e:
        return response(status=401, name=request.url, description=f"ERROR: {e}")
