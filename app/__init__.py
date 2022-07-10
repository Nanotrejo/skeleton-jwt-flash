import os

from flask import Flask
from flask_jwt_extended import JWTManager

from extensions import mongo

MONGODB_URI = os.environ.get("MONGODB_URI")

app = Flask(__name__)
jwt = JWTManager(app)
app.config.from_json(os.path.join("jwt/resources", "config.json"))

from app.controller.user_controller import user_bp
from app.jwt import errors
from app.jwt.api import *
from app.jwt.api.login import auth_bp


def create_app():
    app.config["MONGO_URI"] = MONGODB_URI
    mongo.init_app(app)
    app.register_blueprint(user_bp)
    app.register_blueprint(auth_bp)
    return app
