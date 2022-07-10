import datetime

from flask import Blueprint, abort, make_response, request
from flask.json import jsonify

from app import app
from app.controller import response
from app.jwt.auth import (
    AuthenticationError,
    auth_refresh_required,
    auth_required,
    authenticate_user,
    deauthenticate_user,
    get_authenticated_user,
    refresh_authentication,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/register", methods=["POST"])
def register_user():
    import os

    from werkzeug.security import generate_password_hash

    from app.controller.user_request import check_exists_by_email, create_user

    SECRET_KEY = os.environ.get("SECRET_KEY")
    try:
        req = request.get_json()
        if not check_exists_by_email(req["email"]):
            del req["password2"]
            password = req["password"]
            req["password"] = generate_password_hash(req["password"], method=SECRET_KEY)
            req["enabled"] = True
            req["google"] = False
            req["dateInit"] = datetime.datetime.now()
            req["dateLogin"] = datetime.datetime.now()
            req["admin"] = False
            create_user(user=req)
            access_token, refresh_token = authenticate_user(req["email"], password)
            return response(
                200,
                request.url,
                "Create Successful",
                payload={"accessToken": access_token, "refreshToken": refresh_token},
            )
        return response(401, request.url, "Email already exists -> " + req["email"])

    except AuthenticationError as error:
        app.logger.error("authentication error: %s", error)
        abort(403)


@auth_bp.route("/login", methods=["POST"])
def login_api():

    try:
        from app.controller import response
        from app.controller.user_request import set_datetime_login

        email = request.json.get("email", None)
        password = request.json.get("password", None)
        access_token, refresh_token = authenticate_user(email, password)
        set_datetime_login(email)
        return response(
            200,
            request.url,
            "Login Successful",
            {"accessToken": access_token, "refreshToken": refresh_token},
        )
    except AuthenticationError as error:
        app.logger.error("authentication error: %s", error)
        abort(403)


@auth_bp.route("/info", methods=["GET"])
@auth_required
# @jwt_required
def login_info_api():
    """
    Get information about currently logged in user
    """
    try:
        user = get_authenticated_user()
        return make_response(
            jsonify(
                {
                    "name": user["name"],
                    "lastname": user["lastname"],
                    "email": user["email"],
                    "google": user["google"],
                    "dateInit": user["dateInit"],
                    "dateLogin": user["dateLogin"]
                }
            )
        )
    except AuthenticationError as error:
        app.logger.error("authentication error: %s", error)
        abort(403)


@auth_bp.route("/logout", methods=["POST"])
@auth_refresh_required
def logout_api():
    deauthenticate_user()
    return make_response()


@auth_bp.route("/refresh", methods=["POST"])
@auth_refresh_required
def refresh_api():
    """
    Get a fresh access token from a valid refresh token
    """
    try:
        access_token = refresh_authentication()
        return make_response(jsonify({"accessToken": access_token}))
    except AuthenticationError as error:
        app.logger.error("authentication error %s", error)
        abort(403)
