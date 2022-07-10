import datetime
import os
from functools import wraps

from flask_jwt_extended import (  # verify_jwt_refresh_token_in_request,
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request,
)
from werkzeug.security import check_password_hash

from app import app
from app.controller.user_request import (
    check_exists_by_email,
    get_user_by_email,
    get_users_array,
)

SECRET_KEY = os.environ.get("SECRET_KEY")


class AuthenticationError(Exception):
    """Base Authentication Exception"""

    def __init__(self, msg=None):
        self.msg = msg

    def __str__(self):
        return self.__class__.__name__ + "(" + str(self.msg) + ")"


class InvalidCredentials(AuthenticationError):
    """Invalid username/password"""


class AccountInactive(AuthenticationError):
    """Account is disabled"""


class AccessDenied(AuthenticationError):
    """Access is denied"""


class UserNotFound(AuthenticationError):
    """User identity not found"""


def authenticate_user(email: str, password: str):

    if check_exists_by_email(email):
        user = get_user_by_email(email)
        if email == user["email"] and check_password_hash(user["password"], password):
            if user["enabled"]:
                return (
                    create_access_token(
                        identity=email, expires_delta=datetime.timedelta(days=365)
                    ),
                    create_refresh_token(
                        identity=email, expires_delta=datetime.timedelta(days=365)
                    ),
                )
            else:
                raise AccountInactive(email)
        else:
            raise InvalidCredentials()
    raise InvalidCredentials()


# @jwt_required
def get_authenticated_user():
    """
    Get authentication token user identity and verify account is active
    """
    identity = get_jwt_identity()

    for user in get_users_array():
        if identity == user["email"]:
            if user["enabled"]:
                return user
            else:
                raise AccountInactive()
    else:
        raise UserNotFound(identity)


def deauthenticate_user():

    identity = get_jwt_identity()
    app.logger.debug('logging user "%s" out', identity)


def refresh_authentication():
    """
    Refresh authentication, issue new access token
    """
    user = get_authenticated_user()
    return create_access_token(identity=user["email"])


def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        try:
            get_authenticated_user()
            return func(*args, **kwargs)
        except (UserNotFound, AccountInactive) as error:
            app.logger.error("authorization failed: %s", error)
            abort(403)

    return wrapper


@jwt_required
def auth_refresh_required(func):
    """
    View decorator - require valid refresh token
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # verify_jwt_refresh_token_in_request()
        # jwt_required()
        try:
            get_authenticated_user()
            return func(*args, **kwargs)
        except (UserNotFound, AccountInactive) as error:
            app.logger.error("authorization failed: %s", error)
            abort(403)

    return wrapper


def admin_required(func):
    """
    View decorator - required valid access token and admin access
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        try:
            user = get_authenticated_user()
            if user["is_admin"]:
                return func(*args, **kwargs)
            else:
                abort(403)
        except (UserNotFound, AccountInactive) as error:
            app.logger.error("authorization failed: %s", error)
            abort(403)

    return wrapper
